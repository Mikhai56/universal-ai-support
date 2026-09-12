#!/usr/bin/env python3
"""SupportPilot Telegram MVP — stdlib-only bot with SQLite and optional OpenAI."""
import html, json, os, sqlite3, time, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()
DB_PATH = os.getenv("DB_PATH", str(BASE / "supportpilot.db"))
KB_PATH = os.getenv("KB_PATH", str(BASE / "knowledge_base.json"))
TG_API = f"https://api.telegram.org/bot{TOKEN}"

with open(KB_PATH, encoding="utf-8") as f:
    KB = json.load(f)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS tickets(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      chat_id TEXT NOT NULL, username TEXT, question TEXT NOT NULL,
      answer TEXT, status TEXT NOT NULL, reason TEXT,
      created_at TEXT NOT NULL, resolved_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER,
      chat_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL,
      created_at TEXT NOT NULL)""")
    conn.commit()
    return conn


def now(): return datetime.now(timezone.utc).isoformat()


def api(method, payload=None):
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(f"{TG_API}/{method}", data=data,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=65) as r:
        result = json.loads(r.read().decode())
    if not result.get("ok"):
        raise RuntimeError(result)
    return result["result"]


def send(chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup: payload["reply_markup"] = reply_markup
    return api("sendMessage", payload)


def local_answer(question):
    low = question.lower()
    best, score = None, 0
    for item in KB:
        current = sum(1 for k in item["keywords"] if k.lower() in low)
        if current > score: best, score = item, current
    if best and score:
        return best["answer"], float(best.get("confidence", .75)), best["topic"]
    return None, 0.0, "unknown"


def risky(question):
    low = question.lower()
    groups = {
      "платёж или возврат": ["оплат", "платеж", "платёж", "карт", "возврат", "деньг"],
      "персональные данные": ["удал", "данн", "приват", "privacy", "паспорт"],
      "юридический вопрос": ["суд", "юрист", "закон", "претензи", "договор"],
      "безопасность": ["взлом", "утеч", "пароль укра", "мошенн"]
    }
    for reason, words in groups.items():
        if any(w in low for w in words): return reason
    return None


def openai_answer(question):
    if not OPENAI_API_KEY: return None
    kb_text = "\n".join(f"- {x['topic']}: {x['answer']}" for x in KB)
    body = {
      "model": OPENAI_MODEL,
      "input": [
        {"role":"system","content":[{"type":"input_text","text":
          "Ты сотрудник первой линии поддержки. Отвечай по-русски, кратко и только по базе знаний. "
          "Не проси пароли, данные карты или документы. Если данных мало, напиши ESCALATE."}]},
        {"role":"user","content":[{"type":"input_text","text":f"База знаний:\n{kb_text}\n\nВопрос: {question}"}]}
      ]
    }
    req = urllib.request.Request("https://api.openai.com/v1/responses",
      data=json.dumps(body).encode(), headers={"Content-Type":"application/json","Authorization":f"Bearer {OPENAI_API_KEY}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            out = json.loads(r.read().decode())
        text = out.get("output_text")
        if not text:
            for item in out.get("output", []):
                for c in item.get("content", []):
                    if c.get("type") == "output_text": text = c.get("text")
        return text
    except Exception as e:
        print("OpenAI error:", e)
        return None


def create_ticket(chat_id, username, question, answer, status, reason):
    conn = db()
    cur = conn.execute("INSERT INTO tickets(chat_id,username,question,answer,status,reason,created_at) VALUES(?,?,?,?,?,?,?)",
      (str(chat_id), username, question, answer, status, reason, now()))
    ticket_id = cur.lastrowid
    conn.execute("INSERT INTO messages(ticket_id,chat_id,role,content,created_at) VALUES(?,?,?,?,?)",
      (ticket_id, str(chat_id), "user", question, now()))
    if answer:
        conn.execute("INSERT INTO messages(ticket_id,chat_id,role,content,created_at) VALUES(?,?,?,?,?)",
          (ticket_id, str(chat_id), "assistant", answer, now()))
    conn.commit(); conn.close(); return ticket_id


def escalate(chat_id, username, question, reason):
    answer = "Я передал обращение специалисту, чтобы не дать неточный или небезопасный ответ. История диалога сохранена."
    ticket_id = create_ticket(chat_id, username, question, answer, "escalated", reason)
    send(chat_id, f"🧑‍💼 {answer}\n\nНомер обращения: <b>#{ticket_id}</b>")
    if ADMIN_CHAT_ID:
        send(ADMIN_CHAT_ID, f"🚨 <b>Новая эскалация #{ticket_id}</b>\nПричина: {html.escape(reason)}\nКлиент: @{html.escape(username or 'без username')}\n\n{html.escape(question)}\n\nЗакрыть: /resolve_{ticket_id}")


def queue(chat_id):
    conn=db(); rows=conn.execute("SELECT id,username,question,reason,created_at FROM tickets WHERE status='escalated' ORDER BY id DESC LIMIT 10").fetchall(); conn.close()
    if not rows: return send(chat_id, "Очередь эскалаций пуста.")
    text="<b>Открытые эскалации</b>\n\n"+"\n\n".join(f"#{r['id']} · @{html.escape(r['username'] or '—')}\n{html.escape(r['reason'] or '—')}\n{html.escape(r['question'][:180])}" for r in rows)
    send(chat_id,text)


def resolve(chat_id, ticket_id):
    conn=db(); row=conn.execute("SELECT chat_id FROM tickets WHERE id=? AND status='escalated'",(ticket_id,)).fetchone()
    if not row: conn.close(); return send(chat_id,"Тикет не найден или уже закрыт.")
    conn.execute("UPDATE tickets SET status='resolved', resolved_at=? WHERE id=?",(now(),ticket_id)); conn.commit(); conn.close()
    send(chat_id,f"✅ Тикет #{ticket_id} закрыт."); send(row['chat_id'],f"✅ Обращение #{ticket_id} отмечено как решённое специалистом.")


def handle(message):
    chat_id=message["chat"]["id"]; text=(message.get("text") or "").strip(); user=message.get("from",{}); username=user.get("username") or user.get("first_name","")
    if not text: return send(chat_id,"Пока я понимаю только текстовые сообщения.")
    if text == "/start":
        return send(chat_id,"Здравствуйте! Я — SupportPilot. Помогу с типовыми вопросами, а сложный случай передам специалисту.\n\nНапишите ваш вопрос одним сообщением.")
    if text in ("/help","/privacy"):
        return send(chat_id,"Не отправляйте пароли, данные банковской карты и документы. Сообщения сохраняются для обработки обращения. Для связи со специалистом: /operator")
    if text == "/operator": return escalate(chat_id,username,"Клиент запросил оператора","запрос клиента")
    is_admin = ADMIN_CHAT_ID and str(chat_id)==str(ADMIN_CHAT_ID)
    if is_admin and text == "/queue": return queue(chat_id)
    if is_admin and text.startswith("/resolve_"):
        try: return resolve(chat_id,int(text.split("_",1)[1]))
        except ValueError: return send(chat_id,"Неверный номер тикета.")
    reason=risky(text)
    if reason: return escalate(chat_id,username,text,reason)
    answer,confidence,topic=local_answer(text)
    if not answer:
        ai=openai_answer(text)
        if not ai or "ESCALATE" in ai.upper(): return escalate(chat_id,username,text,"недостаточно данных")
        answer=ai; confidence=.65; topic="AI"
    ticket_id=create_ticket(chat_id,username,text,answer,"answered",topic)
    send(chat_id,f"🤖 {html.escape(answer)}\n\n<i>Обращение #{ticket_id} · если ответ не помог, отправьте /operator</i>")


def run():
    if not TOKEN: raise SystemExit("Set TELEGRAM_BOT_TOKEN")
    db().close(); offset=0; print("SupportPilot started")
    while True:
        try:
            updates=api("getUpdates",{"offset":offset,"timeout":50,"allowed_updates":["message"]})
            for upd in updates:
                offset=upd["update_id"]+1
                if "message" in upd: handle(upd["message"])
        except (urllib.error.URLError, TimeoutError, RuntimeError) as e:
            print("Polling error:",e); time.sleep(3)
        except KeyboardInterrupt: break

if __name__ == "__main__": run()
