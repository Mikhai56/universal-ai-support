#!/usr/bin/env python3
"""SupportPilot web app: AI support + knowledge base + persistent tickets."""
import html
import json
import os
import re
import sqlite3
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
DB_PATH = os.getenv("DB_PATH", str(BASE / "supportpilot.db"))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
AI_API_KEY = os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("AI_GATEWAY_API_KEY")
AI_BASE_URL = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")
MAX_MESSAGE_CHARS = min(max(int(os.getenv("MAX_MESSAGE_CHARS", "4096")), 128), 16384)

with open(BASE / "knowledge_base.json", encoding="utf-8") as f:
    KB = json.load(f)


def using_postgres():
    return bool(DATABASE_URL)


def db():
    if using_postgres():
        try:
            import psycopg
            conn = psycopg.connect(DATABASE_URL, connect_timeout=10)
            conn.row_factory = psycopg.rows.dict_row
            return conn
        except Exception as exc:
            print(f"Postgres unavailable, using SQLite fallback: {exc}", flush=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = db()
    if using_postgres() and conn.__class__.__module__.startswith("psycopg"):
        conn.execute("""CREATE TABLE IF NOT EXISTS tickets(
            id BIGSERIAL PRIMARY KEY,
            chat_id TEXT NOT NULL,
            username TEXT,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            resolved_at TIMESTAMPTZ
        )""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT NOT NULL,
            username TEXT,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL,
            resolved_at TEXT
        )""")
    conn.commit()
    conn.close()


def words(text):
    stop = {"как", "какой", "какая", "какие", "что", "это", "есть", "ли", "вы", "можно", "нужно", "для", "при", "по", "на", "мне"}
    return {w for w in re.findall(r"[a-zа-яё0-9]+", text.lower()) if len(w) > 2 and w not in stop}


def local_answer(question):
    normalized = question.lower().strip()
    question_words = words(normalized)
    best = None
    best_score = 0.0
    for item in KB:
        for pattern in item.get("questions", []) + item.get("keywords", []):
            candidate = pattern.lower().strip()
            candidate_words = words(candidate)
            score = max(
                1.0 if candidate in normalized or normalized in candidate else 0.0,
                len(question_words & candidate_words) / max(1, len(candidate_words)),
            )
            if score > best_score:
                best, best_score = item, score
    if best and best_score >= 0.45:
        return best["answer"], best.get("topic") or best.get("id", "База знаний"), bool(best.get("escalate")), best.get("source")
    return None, "unknown", False, None


def risky(question):
    normalized = question.lower()
    groups = {
        "платёжный инцидент": ["списали дважды", "двойное списание", "вернуть деньги", "данные карты", "номер карты", "cvv"],
        "персональные данные": ["покажи данные другого", "чужие данные", "удали мои данные", "паспорт"],
        "юридический вопрос": ["подам в суд", "юрист", "претензия", "нарушение закона"],
        "безопасность": ["взломали", "утечка", "украли пароль", "мошенничество"],
    }
    for reason, phrases in groups.items():
        if any(p in normalized for p in phrases):
            return reason
    return None


def redact_sensitive(text):
    text = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "[ДАННЫЕ КАРТЫ УДАЛЕНЫ]", text)
    return re.sub(r"(?i)\b(cvv|cvc)\s*[:=]?\s*\d{3,4}\b", r"\1 [УДАЛЕНО]", text)


def create_ticket(question, answer, status, reason):
    conn = db()
    q = redact_sensitive(question)
    a = redact_sensitive(answer)
    if using_postgres() and conn.__class__.__module__.startswith("psycopg"):
        cur = conn.execute(
            "INSERT INTO tickets(chat_id,username,question,answer,status,reason) VALUES(%s,%s,%s,%s,%s,%s) RETURNING id",
            ("web", "web-user", q, a, status, reason),
        )
        ticket_id = cur.fetchone()["id"]
    else:
        cur = conn.execute(
            "INSERT INTO tickets(chat_id,username,question,answer,status,reason,created_at) VALUES(?,?,?,?,?,?,datetime('now'))",
            ("web", "web-user", q, a, status, reason),
        )
        ticket_id = cur.lastrowid
    conn.commit()
    conn.close()
    return ticket_id


def ai_answer(question):
    if not AI_API_KEY:
        return None
    kb_context = json.dumps(KB, ensure_ascii=False)
    payload = {
        "model": AI_MODEL,
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Ты SupportPilot — оператор поддержки интернет-магазина. "
                    "Отвечай только на основе переданной базы знаний. "
                    "Не выдумывай цены, сроки, наличие, статусы заказов или правила. "
                    "Если в базе нет ответа, прямо скажи, что вопрос нужно передать менеджеру. "
                    "Никогда не проси пароль, CVV или полные реквизиты карты. "
                    "Отвечай кратко и по-русски.\n\nБАЗА ЗНАНИЙ:\n" + kb_context
                ),
            },
            {"role": "user", "content": question},
        ],
    }
    request = urllib.request.Request(
        AI_BASE_URL + "/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AI_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"].strip()
        return content or None
    except Exception as exc:
        print(f"AI request failed: {exc}", flush=True)
        return None


def answer_question(question):
    question = redact_sensitive((question or "").strip())[:MAX_MESSAGE_CHARS]
    if not question:
        return {"answer": "Напишите вопрос одним сообщением.", "status": "needs_clarification"}

    reason = risky(question)
    if reason:
        answer = "Я передал обращение специалисту, чтобы не дать неточный или небезопасный ответ. Не отправляйте пароли и полные реквизиты карты."
        ticket_id = create_ticket(question, answer, "escalated", reason)
        return {"answer": answer, "status": "escalated", "ticket_id": ticket_id}

    answer, topic, must_escalate, source = local_answer(question)
    if answer and must_escalate:
        ticket_id = create_ticket(question, answer, "escalated", topic)
        return {"answer": answer, "status": "escalated", "ticket_id": ticket_id, "source": source}

    ai = ai_answer(question)
    if ai:
        ticket_id = create_ticket(question, ai, "answered", topic if answer else "AI")
        return {"answer": ai, "status": "answered", "ticket_id": ticket_id, "source": source or "AI"}

    if answer:
        ticket_id = create_ticket(question, answer, "answered", topic)
        return {"answer": answer, "status": "answered", "ticket_id": ticket_id, "source": source}

    fallback = "Я пока не нашёл точного ответа. Уточните вопрос или передам его менеджеру."
    ticket_id = create_ticket(question, fallback, "needs_clarification", "недостаточно данных")
    return {"answer": fallback, "status": "needs_clarification", "ticket_id": ticket_id}


class Handler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self.send_json({
                "ok": True,
                "service": "SupportPilot",
                "mode": "web",
                "database": "postgres" if using_postgres() else "sqlite-fallback",
                "ai": bool(AI_API_KEY),
            })
        if path in ("/", "/index.html"):
            file = BASE / "web" / "index.html"
            body = file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/chat":
            return self.send_json({"error": "not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1_000_000:
                return self.send_json({"error": "request too large"}, 413)
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = answer_question(payload.get("message", ""))
            return self.send_json(result)
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error": "invalid JSON"}, 400)
        except Exception as exc:
            return self.send_json({"error": "internal error", "detail": str(exc)}, 500)

    def log_message(self, fmt, *args):
        print("WEB", fmt % args, flush=True)


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"SupportPilot web app listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()
