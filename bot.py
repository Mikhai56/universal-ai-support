#!/usr/bin/env python3
"""SupportPilot Telegram bot: sourced KB, SQLite, human escalation."""
import html, json, os, random, re, sqlite3, time, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID", "").strip()
DB_PATH = os.getenv("DB_PATH", "/var/data/supportpilot.db")
KB_PATH = os.getenv("KB_PATH", str(BASE / "knowledge_base.json"))
TG_API = "https://api.telegram.org/bot" + TOKEN

def positive_int(name, default, minimum=1, maximum=1_000_000):
    try: value = int(os.getenv(name, str(default)))
    except ValueError: return default
    return min(max(value, minimum), maximum)

def positive_float(name, default, minimum=0.0, maximum=60.0):
    try: value = float(os.getenv(name, str(default)))
    except ValueError: return default
    return min(max(value, minimum), maximum)

MAX_MESSAGE_CHARS = positive_int("MAX_MESSAGE_CHARS", 4096, 128, 16384)
RATE_LIMIT_SECONDS = positive_float("RATE_LIMIT_SECONDS", 1.0)
RETENTION_DAYS = positive_int("RETENTION_DAYS", 90, 1, 3650)
LAST_MESSAGE_AT = {}
with open(KB_PATH, encoding="utf-8") as file: KB = json.load(file)

def now(): return datetime.now(timezone.utc).isoformat()
def _open_db(path):
    conn=sqlite3.connect(path,timeout=10); conn.row_factory=sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY AUTOINCREMENT,chat_id TEXT NOT NULL,username TEXT,question TEXT NOT NULL,answer TEXT,status TEXT NOT NULL,reason TEXT,created_at TEXT NOT NULL,resolved_at TEXT)""")
    conn.commit(); return conn
def db():
    try:
        return _open_db(DB_PATH)
    except sqlite3.OperationalError as error:
        if "readonly" not in str(error).lower() and "read-only" not in str(error).lower(): raise
        fallback="/tmp/supportpilot.db"
        print(f"SQLite path {DB_PATH!r} is not writable; using {fallback!r}: {error}",flush=True)
        return _open_db(fallback)

def cleanup_old_tickets():
    cutoff=(datetime.now(timezone.utc)-timedelta(days=RETENTION_DAYS)).isoformat()
    conn=db(); conn.execute("DELETE FROM tickets WHERE created_at < ?",(cutoff,)); conn.commit(); conn.close()

def api(method,payload=None):
    req=urllib.request.Request(f"{TG_API}/{method}",data=json.dumps(payload or {}).encode(),headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=65) as response: result=json.loads(response.read().decode())
    if not result.get("ok"): raise RuntimeError(result)
    return result["result"]
def send(chat_id,text): return api("sendMessage",{"chat_id":chat_id,"text":text,"parse_mode":"HTML"})

def redact_sensitive(text):
    text=re.sub(r"\b(?:\d[ -]*?){13,19}\b","[ДАННЫЕ КАРТЫ УДАЛЕНЫ]",text)
    return re.sub(r"(?i)\b(cvv|cvc)\s*[:=]?\s*\d{3,4}\b",r"\1 [УДАЛЕНО]",text)

def safe_text(text): return redact_sensitive((text or "").strip())[:MAX_MESSAGE_CHARS]

def rate_limited(chat_id):
    current=time.monotonic(); previous=LAST_MESSAGE_AT.get(str(chat_id),0.0)
    LAST_MESSAGE_AT[str(chat_id)]=current
    if len(LAST_MESSAGE_AT)>10000:
        cutoff=current-max(RATE_LIMIT_SECONDS*10,60)
        for key,value in list(LAST_MESSAGE_AT.items()):
            if value<cutoff: LAST_MESSAGE_AT.pop(key,None)
    return current-previous<RATE_LIMIT_SECONDS

def words(text):
    stop={"как","какой","какая","какие","что","это","есть","ли","вы","можно","нужно","для","при","по","на","мне"}
    return {w for w in re.findall(r"[a-zа-яё0-9]+",text.lower()) if len(w)>2 and w not in stop}
def local_answer(question):
    normalized=question.lower().strip(); question_words=words(normalized); best=None; best_score=0.0
    for item in KB:
        for pattern in item.get("questions",[])+item.get("keywords",[]):
            candidate=pattern.lower().strip(); candidate_words=words(candidate)
            score=max(1.0 if candidate in normalized or normalized in candidate else 0.0,len(question_words & candidate_words)/max(1,len(candidate_words)))
            if score>best_score: best,best_score=item,score
    if best and best_score>=0.45:
        return best["answer"],best.get("topic") or best.get("id","База знаний"),bool(best.get("escalate")),best.get("source")
    return None,"unknown",False,None

def risky(question):
    normalized=question.lower()
    groups={"платёжный инцидент":["списали дважды","двойное списание","вернуть деньги","данные карты","номер карты","cvv"],"персональные данные":["покажи данные другого","чужие данные","удали мои данные","паспорт"],"юридический вопрос":["подам в суд","юрист","претензия","нарушение закона"],"безопасность":["взломали","утечка","украли пароль","мошенничество"]}
    for reason,phrases in groups.items():
        if any(p in normalized for p in phrases): return reason
    return None

def create_ticket(chat_id,username,question,answer,status,reason):
    question=safe_text(question); username=safe_text(username)[:64]; answer=safe_text(answer)
    conn=db(); cur=conn.execute("INSERT INTO tickets(chat_id,username,question,answer,status,reason,created_at) VALUES(?,?,?,?,?,?,?)",(str(chat_id),username,question,answer,status,reason,now()))
    ticket_id=cur.lastrowid; conn.commit(); conn.close(); return ticket_id

def escalate(chat_id,username,question,reason,public_answer=None):
    question=safe_text(question)
    answer=public_answer or "Я передал обращение специалисту, чтобы не дать неточный или небезопасный ответ. История диалога сохранена на ограниченный срок."
    ticket_id=create_ticket(chat_id,username,question,answer,"escalated",reason)
    send(chat_id,f"🧑‍💼 {html.escape(answer)}\n\nНомер обращения: <b>#{ticket_id}</b>")
    if ADMIN_CHAT_ID: send(ADMIN_CHAT_ID,f"🚨 <b>Новая эскалация #{ticket_id}</b>\nПричина: {html.escape(reason)}\nКлиент: @{html.escape((username or 'без username')[:64])}\n\n{html.escape(question)}\n\nЗакрыть: /resolve_{ticket_id}")

def show_queue(chat_id):
    conn=db(); rows=conn.execute("SELECT id,username,question,reason FROM tickets WHERE status='escalated' ORDER BY id DESC LIMIT 10").fetchall(); conn.close()
    if not rows: return send(chat_id,"Очередь эскалаций пуста.")
    items=[f"#{r['id']} · @{html.escape(r['username'] or '—')}\n{html.escape(r['reason'] or '—')}\n{html.escape(r['question'][:180])}" for r in rows]
    send(chat_id,"<b>Открытые эскалации</b>\n\n"+"\n\n".join(items))
def resolve(chat_id,ticket_id):
    conn=db(); row=conn.execute("SELECT chat_id FROM tickets WHERE id=? AND status='escalated'",(ticket_id,)).fetchone()
    if not row: conn.close(); return send(chat_id,"Тикет не найден или уже закрыт.")
    conn.execute("UPDATE tickets SET status='resolved',resolved_at=? WHERE id=?",(now(),ticket_id)); conn.commit(); conn.close()
    send(chat_id,f"✅ Тикет #{ticket_id} закрыт."); send(row["chat_id"],f"✅ Обращение #{ticket_id} отмечено как решённое специалистом.")

def handle(message):
    chat_id=message["chat"]["id"]; raw_text=message.get("text") or ""; user=message.get("from",{}); username=safe_text(user.get("username") or user.get("first_name", ""))[:64]
    if len(raw_text)>MAX_MESSAGE_CHARS: return send(chat_id,f"Сообщение слишком длинное. Максимум: {MAX_MESSAGE_CHARS} символов.")
    text=raw_text.strip()
    if not text: return send(chat_id,"Пока я понимаю только текстовые сообщения.")
    if text=="/start": return send(chat_id,"Здравствуйте! Я — SupportPilot. Отвечу на типовые вопросы о «Юнити96», а сложный случай передам специалисту.\n\nНапишите вопрос одним сообщением.")
    if text in ("/help","/privacy"): return send(chat_id,f"Не отправляйте пароли, данные банковской карты и документы. Обращения хранятся не более {RETENTION_DAYS} дней. Для связи со специалистом: /operator")
    is_admin=bool(ADMIN_CHAT_ID) and str(chat_id)==str(ADMIN_CHAT_ID)
    if is_admin and text=="/queue": return show_queue(chat_id)
    if is_admin and text.startswith("/resolve_"):
        try: return resolve(chat_id,int(text.split("_",1)[1]))
        except ValueError: return send(chat_id,"Неверный номер тикета.")
    if rate_limited(chat_id): return send(chat_id,"Слишком много сообщений. Подождите немного и повторите.")
    if text=="/operator": return escalate(chat_id,username,"Клиент запросил оператора","запрос клиента")
    reason=risky(text)
    if reason: return escalate(chat_id,username,text,reason)
    answer,topic,must_escalate,source=local_answer(text)
    if answer and must_escalate: return escalate(chat_id,username,text,topic,answer)
    if not answer:
        answer="Я пока не нашёл точного ответа. Уточните вопрос или выберите тему: ассортимент, доставка, сборка, оплата, возврат, гарантия, контакты или статус заказа."
        ticket_id=create_ticket(chat_id,username,text,answer,"needs_clarification","недостаточно данных")
        return send(chat_id,f"🤔 {answer}\n\n<i>Обращение #{ticket_id}</i>")
    ticket_id=create_ticket(chat_id,username,text,answer,"answered",topic)
    source_line=f"\nИсточник: {html.escape(source)}" if source and source.startswith("http") else ""
    send(chat_id,f"🤖 {html.escape(answer)}{source_line}\n\n<i>Обращение #{ticket_id} · если ответ не помог, отправьте /operator</i>")

def run():
    if not TOKEN: raise SystemExit("Set TELEGRAM_BOT_TOKEN")
    db().close(); cleanup_old_tickets(); offset=0; print("SupportPilot started",flush=True)
    retry_delay = 1.0
    max_retry_delay = 60.0
    while True:
        try:
            updates=api("getUpdates",{"offset":offset,"timeout":50,"allowed_updates":["message"]})
            retry_delay = 1.0
            for update in updates:
                offset=update["update_id"]+1
                if "message" in update: handle(update["message"])
        except (urllib.error.URLError,TimeoutError,RuntimeError,ValueError,sqlite3.Error) as error:
            jitter=random.uniform(0, min(1.0, retry_delay * 0.25))
            delay=retry_delay + jitter
            print(f"Polling error: {error}; retrying in {delay:.1f}s",flush=True)
            time.sleep(delay)
            retry_delay=min(max_retry_delay, retry_delay * 2)
        except KeyboardInterrupt: break
if __name__=="__main__": run()
