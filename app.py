#!/usr/bin/env python3
"""SupportPilot — production-minded AI customer support app."""
import hashlib, html, json, os, re, secrets, sqlite3, time, urllib.request, urllib.error
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
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@supportpilot.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
MAX_MESSAGE_CHARS = min(max(int(os.getenv("MAX_MESSAGE_CHARS", "4096")), 128), 16384)
TOKEN_TTL = 60 * 60 * 12
LEAD_RATE_WINDOW = 60
LEAD_RATE_MAX = 10
LEAD_RATE = {}

with open(BASE / "knowledge_base.json", encoding="utf-8") as f:
    KB = json.load(f)
SESSIONS = {}

def pg_conn():
    import psycopg
    conn = psycopg.connect(DATABASE_URL, connect_timeout=10)
    conn.row_factory = psycopg.rows.dict_row
    return conn

def db():
    if DATABASE_URL:
        try: return pg_conn()
        except Exception as exc: print(f"Postgres unavailable, SQLite fallback: {exc}", flush=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def is_pg(conn): return conn.__class__.__module__.startswith("psycopg")

def init_db():
    conn = db()
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS tickets(
          id BIGSERIAL PRIMARY KEY, chat_id TEXT NOT NULL, username TEXT, question TEXT NOT NULL,
          answer TEXT NOT NULL, status TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'normal',
          reason TEXT, assignee TEXT, customer_email TEXT, customer_name TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          resolved_at TIMESTAMPTZ)""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS tickets(
          id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT NOT NULL, username TEXT,
          question TEXT NOT NULL, answer TEXT NOT NULL, status TEXT NOT NULL,
          priority TEXT NOT NULL DEFAULT 'normal', reason TEXT, assignee TEXT,
          customer_email TEXT, customer_name TEXT, created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL, resolved_at TEXT)""")
    from lead_pipeline import init_leads
    init_leads(conn)
    conn.commit(); conn.close()

def words(text):
    stop={"как","какой","какая","какие","что","это","есть","ли","вы","можно","нужно","для","при","по","на","мне","про"}
    return {w for w in re.findall(r"[a-zа-яё0-9]+", text.lower()) if len(w)>2 and w not in stop}

def local_answer(question):
    q=question.lower(); qw=words(q); best=None; score=0
    for item in KB:
        for pattern in item.get("questions",[])+item.get("keywords",[]):
            p=pattern.lower(); pw=words(p)
            s=max(1 if p in q or q in p else 0, len(qw & pw)/max(1,len(pw)))
            if s>score: best,score=item,s
    if best and score>=.45:
        return best["answer"],best.get("topic") or best.get("id","База знаний"),bool(best.get("escalate")),best.get("source")
    return None,"unknown",False,None

def risky(question):
    q=question.lower()
    groups={
      "платёжный инцидент":["списали дважды","двойное списание","вернуть деньги","данные карты","номер карты","cvv","cvc"],
      "персональные данные":["покажи данные другого","чужие данные","удали мои данные","паспорт"],
      "юридический вопрос":["подам в суд","юрист","претензия","нарушение закона"],
      "безопасность":["взломали","утечка","украли пароль","мошенничество"]
    }
    for reason,phrases in groups.items():
        if any(p in q for p in phrases): return reason
    return None

def redact_sensitive(text):
    text=re.sub(r"\b(?:\d[ -]*?){13,19}\b","[ДАННЫЕ КАРТЫ УДАЛЕНЫ]",text)
    return re.sub(r"(?i)\b(cvv|cvc)\s*[:=]?\s*\d{3,4}\b",r"\1 [УДАЛЕНО]",text)

def create_ticket(question,answer,status,reason="",customer_name="",customer_email=""):
    conn=db(); q=redact_sensitive(question); a=redact_sensitive(answer)
    if is_pg(conn):
        cur=conn.execute("""INSERT INTO tickets(chat_id,username,question,answer,status,priority,reason,customer_name,customer_email)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
          ("web","web-user",q,a,status,"high" if status=="escalated" else "normal",reason,customer_name,customer_email))
        tid=cur.fetchone()["id"]
    else:
        now=time.strftime("%Y-%m-%d %H:%M:%S")
        cur=conn.execute("""INSERT INTO tickets(chat_id,username,question,answer,status,priority,reason,customer_name,customer_email,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)""",("web","web-user",q,a,status,"high" if status=="escalated" else "normal",reason,customer_name,customer_email,now,now))
        tid=cur.lastrowid
    conn.commit(); conn.close(); return tid

def ai_answer(question):
    if not AI_API_KEY: return None
    context=json.dumps(KB,ensure_ascii=False)
    payload={"model":AI_MODEL,"temperature":.2,"messages":[
      {"role":"system","content":"Ты SupportPilot — оператор поддержки интернет-магазина. Отвечай только на основе базы знаний. Не выдумывай цены, сроки, наличие, статусы заказов или правила. Если данных нет — скажи, что нужен менеджер. Никогда не проси пароль, CVV или полные реквизиты карты. Отвечай кратко и по-русски.\nБАЗА ЗНАНИЙ:\n"+context},
      {"role":"user","content":question}]}
    req=urllib.request.Request(AI_BASE_URL+"/chat/completions",data=json.dumps(payload,ensure_ascii=False).encode(),
      headers={"Content-Type":"application/json","Authorization":f"Bearer {AI_API_KEY}"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=25) as r: data=json.loads(r.read().decode())
        return (data["choices"][0]["message"]["content"] or "").strip() or None
    except Exception as exc:
        print(f"AI request failed: {exc}",flush=True); return None

def answer_question(question, name="", email=""):
    question=redact_sensitive((question or "").strip())[:MAX_MESSAGE_CHARS]
    if not question: return {"answer":"Напишите вопрос одним сообщением.","status":"needs_clarification"}
    reason=risky(question)
    if reason:
        answer="Я передал обращение специалисту, чтобы не дать неточный или небезопасный ответ. Не отправляйте пароли и полные реквизиты карты."
        return {"answer":answer,"status":"escalated","ticket_id":create_ticket(question,answer,"escalated",reason,name,email)}
    answer,topic,must_escalate,source=local_answer(question)
    if answer and must_escalate:
        return {"answer":answer,"status":"escalated","ticket_id":create_ticket(question,answer,"escalated",topic,name,email),"source":source}
    ai=ai_answer(question)
    if ai:
        return {"answer":ai,"status":"answered","ticket_id":create_ticket(question,ai,"answered",topic if answer else "AI",name,email),"source":source or "AI"}
    if answer:
        return {"answer":answer,"status":"answered","ticket_id":create_ticket(question,answer,"answered",topic,name,email),"source":source}
    fallback="Я пока не нашёл точного ответа. Уточните вопрос или передам его менеджеру."
    return {"answer":fallback,"status":"needs_clarification","ticket_id":create_ticket(question,fallback,"needs_clarification","недостаточно данных",name,email)}

def row(r):
    return dict(r)

def list_tickets(status=None, limit=100):
    conn=db()
    if is_pg(conn):
        if status: rs=conn.execute("SELECT * FROM tickets WHERE status=%s ORDER BY id DESC LIMIT %s",(status,limit)).fetchall()
        else: rs=conn.execute("SELECT * FROM tickets ORDER BY id DESC LIMIT %s",(limit,)).fetchall()
    else:
        if status: rs=conn.execute("SELECT * FROM tickets WHERE status=? ORDER BY id DESC LIMIT ?",(status,limit)).fetchall()
        else: rs=conn.execute("SELECT * FROM tickets ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    conn.close(); return [row(x) for x in rs]

def update_ticket(tid, fields):
    allowed={"status","priority","assignee","customer_name","customer_email"}
    fields={k:v for k,v in fields.items() if k in allowed}
    if not fields: return None
    conn=db(); pg=is_pg(conn)
    sets=[]; vals=[]
    for k,v in fields.items(): sets.append(f"{k}={'%s' if pg else '?'}"); vals.append(v)
    sets.append("updated_at=NOW()" if pg else "updated_at=datetime('now')")
    if fields.get("status")=="resolved": sets.append("resolved_at=NOW()" if pg else "resolved_at=datetime('now')")
    vals.append(tid)
    q=f"UPDATE tickets SET {', '.join(sets)} WHERE id={'%s' if pg else '?'}"
    conn.execute(q,vals); conn.commit(); conn.close()
    return True

def stats():
    ts=list_tickets(limit=1000)
    return {"total":len(ts),"answered":sum(x["status"]=="answered" for x in ts),
            "escalated":sum(x["status"]=="escalated" for x in ts),
            "open":sum(x["status"] in ("escalated","needs_clarification","open") for x in ts),
            "resolved":sum(x["status"]=="resolved" for x in ts)}

def make_token():
    t=secrets.token_urlsafe(32); SESSIONS[t]=time.time()+TOKEN_TTL; return t

def auth(h):
    token=(h.get("Authorization") or "").replace("Bearer ","").strip()
    if token and token in SESSIONS and SESSIONS[token]>time.time(): return True
    return False

class Handler(BaseHTTPRequestHandler):
    def send_json(self,payload,status=200):
        body=json.dumps(payload,ensure_ascii=False,default=str).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store")
        self.send_header("Access-Control-Allow-Origin", "null" if self.headers.get("Origin") else "*")
        self.end_headers(); self.wfile.write(body)
    def body(self):
        n=int(self.headers.get("Content-Length","0"))
        if n>1_000_000: raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}")
    def require(self):
        if not auth(self.headers): self.send_json({"error":"authentication required"},401); return False
        return True
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin", "null" if self.headers.get("Origin") else "*")
        self.send_header("Access-Control-Allow-Headers","Content-Type, Authorization"); self.send_header("Access-Control-Allow-Methods","GET,POST,PATCH,OPTIONS"); self.end_headers()
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/health":
            return self.send_json({"ok":True,"service":"SupportPilot","version":"2.0","database":"postgres" if DATABASE_URL else "sqlite-fallback","ai":bool(AI_API_KEY),"auth":bool(ADMIN_PASSWORD)})
        if path=="/api/kb":
            return self.send_json({"items":KB,"count":len(KB)})
        if path=="/api/leads":
            if not self.require(): return
            from lead_pipeline import list_leads
            query=urlparse(self.path).query
            status=query[7:] if query.startswith("status=") else None
            return self.send_json({"leads":list_leads(status=status)})
        if path=="/api/tickets":
            if not self.require(): return
            return self.send_json({"tickets":list_tickets()})
        if path=="/api/stats":
            if not self.require(): return
            return self.send_json(stats())
        if path in ("/","/index.html"):
            f=BASE/"web"/"index.html"; b=f.read_bytes()
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
        self.send_json({"error":"not found"},404)
    def do_POST(self):
        path=urlparse(self.path).path
        try: p=self.body()
        except ValueError as e: return self.send_json({"error":str(e)},413 if "large" in str(e) else 400)
        if path=="/api/login":
            email=str(p.get("email","")).strip(); password=str(p.get("password",""))
            if ADMIN_PASSWORD and email==ADMIN_EMAIL and secrets.compare_digest(password,ADMIN_PASSWORD):
                return self.send_json({"ok":True,"token":make_token(),"user":{"email":email,"role":"admin"}})
            if not ADMIN_PASSWORD:
                return self.send_json({"ok":False,"error":"ADMIN_PASSWORD is not configured on the server"},503)
            return self.send_json({"ok":False,"error":"Неверный email или пароль"},401)
        if path=="/api/logout":
            token=(self.headers.get("Authorization") or "").replace("Bearer ","").strip(); SESSIONS.pop(token,None)
            return self.send_json({"ok":True})
        if path=="/api/chat":
            result=answer_question(p.get("message",""),p.get("name",""),p.get("email","")); return self.send_json(result)
        if path=="/api/leads":
            now=time.time()
            client=self.client_address[0]
            recent=[t for t in LEAD_RATE.get(client,[]) if now-t < LEAD_RATE_WINDOW]
            if len(recent) >= LEAD_RATE_MAX:
                LEAD_RATE[client]=recent
                return self.send_json({"error":"too many lead submissions; try again later"},429)
            LEAD_RATE[client]=recent+[now]
            try:
                from lead_pipeline import create_lead
                lead_id=create_lead(p)
            except ValueError as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":True,"leadId":lead_id,"status":"NEW"},202)
        self.send_json({"error":"not found"},404)
    def do_PATCH(self):
        path=urlparse(self.path).path
        if path.startswith("/api/leads/"):
            if not self.require(): return
            try:
                from lead_pipeline import update_lead
                lead_id=path.rsplit("/",1)[1]; ok=update_lead(lead_id,self.body())
            except Exception as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":bool(ok)})
        if path.startswith("/api/tickets/"):
            if not self.require(): return
            try: tid=int(path.rsplit("/",1)[1]); ok=update_ticket(tid,self.body())
            except Exception as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":bool(ok)})
        self.send_json({"error":"not found"},404)
    def log_message(self,fmt,*args): print("WEB",fmt%args,flush=True)

if __name__=="__main__":
    init_db(); ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
