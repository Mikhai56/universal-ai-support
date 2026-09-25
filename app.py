#!/usr/bin/env python3
"""SupportPilot — production-minded AI customer support app."""
import hashlib, html, json, os, re, secrets, sqlite3, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
OPERATORS_JSON = os.getenv("OPERATORS_JSON", "")
MAX_MESSAGE_CHARS = min(max(int(os.getenv("MAX_MESSAGE_CHARS", "4096")), 128), 16384)
TOKEN_TTL = 60 * 60 * 12
PASSWORD_MIN_LENGTH = 12

def validate_password(password):
    password = str(password or "")
    if not PASSWORD_MIN_LENGTH <= len(password) <= 256:
        raise ValueError("password must be 12-256 characters")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
        raise ValueError("password must include uppercase, lowercase, and a digit")
    return password
SESSION_COOKIE_NAME = "sp_session"
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "0").strip().lower() in {"1", "true", "yes", "on"}

def session_cookie(token, max_age=TOKEN_TTL):
    secure = "; Secure" if SECURE_COOKIES else ""
    return f"{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={int(max_age)}{secure}"

def clear_session_cookie():
    secure = "; Secure" if SECURE_COOKIES else ""
    return f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
LEAD_RATE_WINDOW = 60
LEAD_RATE_MAX = 10
LEAD_RATE = {}
CHAT_RATE_WINDOW = 60
CHAT_RATE_MAX = 30
CHAT_RATE = {}
LOGIN_RATE_WINDOW = 300
LOGIN_RATE_MAX = 8
LOGIN_RATE = {}

with open(BASE / "knowledge_base.json", encoding="utf-8") as f:
    KB = json.load(f)
SESSIONS = {}
ROLE_PERMISSIONS = {"admin":{"read","write","manage"},"operator":{"read","write"},"viewer":{"read"}}

def hash_password(password, salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000)
    return "pbkdf2$210000$"+salt.hex()+"$"+digest.hex()

def verify_password(password, encoded):
    try:
        _, rounds, salt_hex, digest_hex=encoded.split("$",3)
        digest=hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return secrets.compare_digest(digest.hex(),digest_hex)
    except Exception:
        return False

def seed_operators(conn):
    users=[]
    if ADMIN_PASSWORD: users.append((str(ADMIN_EMAIL).strip().lower(),ADMIN_PASSWORD,"admin"))
    if OPERATORS_JSON:
        try:
            raw=json.loads(OPERATORS_JSON)
            if isinstance(raw,list):
                for u in raw:
                    if isinstance(u,dict) and u.get("email") and u.get("password") and u.get("role") in ROLE_PERMISSIONS:
                        users.append((str(u["email"]).strip().lower(),str(u["password"]),u["role"]))
        except Exception:
            print("Invalid OPERATORS_JSON",flush=True)
    for email,password,role in users:
        existing=conn.execute("SELECT email FROM operators WHERE email="+("%s" if is_pg(conn) else "?"),(email,)).fetchone()
        if existing: continue
        validate_password(password)
        encoded=hash_password(password)
        if is_pg(conn): conn.execute("INSERT INTO operators(email,password_hash,role) VALUES(%s,%s,%s)",(email,encoded,role))
        else: conn.execute("INSERT INTO operators(email,password_hash,role,created_at) VALUES(?,?,?,datetime('now'))",(email,encoded,role))

def list_operators():
    conn=db(); rs=conn.execute("SELECT email,role,created_at FROM operators ORDER BY email").fetchall(); conn.close()
    return [row(x) for x in rs]

def create_operator(email,password,role):
    email=str(email or "").strip().lower(); password=str(password or "")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): raise ValueError("invalid operator email")
    validate_password(password)
    if role not in ROLE_PERMISSIONS: raise ValueError("invalid operator role")
    conn=db(); exists=conn.execute("SELECT email FROM operators WHERE email="+("%s" if is_pg(conn) else "?"),(email,)).fetchone()
    if exists: conn.close(); raise ValueError("operator already exists")
    encoded=hash_password(password)
    if is_pg(conn): conn.execute("INSERT INTO operators(email,password_hash,role) VALUES(%s,%s,%s)",(email,encoded,role))
    else: conn.execute("INSERT INTO operators(email,password_hash,role,created_at) VALUES(?,?,?,datetime('now'))",(email,encoded,role))
    conn.commit(); conn.close(); return True

def update_operator(email,fields):
    email=str(email or "").strip().lower(); fields={k:v for k,v in (fields or {}).items() if k in {"role","password"}}
    if not fields: return False
    if "role" in fields and fields["role"] not in ROLE_PERMISSIONS: raise ValueError("invalid operator role")
    if "password" in fields: validate_password(fields["password"])
    conn=db(); op=conn.execute("SELECT email,role FROM operators WHERE email="+("%s" if is_pg(conn) else "?"),(email,)).fetchone()
    if not op: conn.close(); return False
    old_role=op["role"]
    new_role=fields.get("role",old_role)
    if old_role=="admin" and new_role!="admin":
        count=conn.execute("SELECT COUNT(*) AS n FROM operators WHERE role='admin'").fetchone()["n"]
        if count<=1: conn.close(); raise ValueError("cannot remove the last admin")
    sets=[]; vals=[]
    if "role" in fields: sets.append("role="+("%s" if is_pg(conn) else "?")); vals.append(new_role)
    if "password" in fields: sets.append("password_hash="+("%s" if is_pg(conn) else "?")); vals.append(hash_password(str(fields["password"])))
    vals.append(email); conn.execute("UPDATE operators SET "+", ".join(sets)+" WHERE email="+("%s" if is_pg(conn) else "?"),vals)
    conn.commit(); conn.close(); return True

def delete_operator(email):
    email=str(email or "").strip().lower(); conn=db()
    op=conn.execute("SELECT role FROM operators WHERE email="+("%s" if is_pg(conn) else "?"),(email,)).fetchone()
    if not op: conn.close(); return False
    if op["role"]=="admin":
        count=conn.execute("SELECT COUNT(*) AS n FROM operators WHERE role='admin'").fetchone()["n"]
        if count<=1: conn.close(); raise ValueError("cannot delete the last admin")
    conn.execute("DELETE FROM operators WHERE email="+("%s" if is_pg(conn) else "?"),(email,)); conn.commit(); conn.close()
    for t,s in list(SESSIONS.items()):
        if s.get("email")==email: SESSIONS.pop(t,None)
    return True

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
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS ticket_events(
          id BIGSERIAL PRIMARY KEY, ticket_id BIGINT NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, details TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS ticket_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL)""")
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS operators(
          email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK (role IN ('admin','operator','viewer')))
        """)
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS operators(
          email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
          created_at TEXT NOT NULL, CHECK (role IN ('admin','operator','viewer')))
        """)
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS conversations(
          id TEXT PRIMARY KEY, customer_name TEXT, customer_email TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("""CREATE TABLE IF NOT EXISTS messages(
          id BIGSERIAL PRIMARY KEY, conversation_id TEXT NOT NULL, role TEXT NOT NULL,
          content TEXT NOT NULL, status TEXT, ticket_id BIGINT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS conversations(
          id TEXT PRIMARY KEY, customer_name TEXT, customer_email TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL, role TEXT NOT NULL,
          content TEXT NOT NULL, status TEXT, ticket_id INTEGER, created_at TEXT NOT NULL)""")
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS notifications(
          id BIGSERIAL PRIMARY KEY, recipient TEXT, kind TEXT NOT NULL, title TEXT NOT NULL,
          body TEXT, ticket_id BIGINT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), read_at TIMESTAMPTZ)""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS notifications(
          id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, kind TEXT NOT NULL, title TEXT NOT NULL,
          body TEXT, ticket_id INTEGER, created_at TEXT NOT NULL, read_at TEXT)""")
    seed_operators(conn)
    init_finance_db(conn)
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
    if status in ("escalated","needs_clarification"):
        create_notification("ticket","Новое обращение требует внимания",f"Обращение #{tid}: {reason or status}",tid,conn=conn)
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

def save_message(conversation_id, role, content, status="", ticket_id=None):
    conn=db(); pg=is_pg(conn); content=redact_sensitive(str(content))[:MAX_MESSAGE_CHARS]
    if pg: conn.execute("INSERT INTO messages(conversation_id,role,content,status,ticket_id) VALUES(%s,%s,%s,%s,%s)",(conversation_id,role,content,status,ticket_id))
    else: conn.execute("INSERT INTO messages(conversation_id,role,content,status,ticket_id,created_at) VALUES(?,?,?,?,?,datetime('now'))",(conversation_id,role,content,status,ticket_id))
    conn.commit(); conn.close()

def ensure_conversation(name="", email="", conversation_id=""):
    cid=str(conversation_id or "").strip()
    if not re.fullmatch(r"[a-f0-9]{32}",cid): cid=secrets.token_hex(16)
    name=str(name or "").strip()[:120]; email=str(email or "").strip().lower()[:254]
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    found=conn.execute("SELECT id FROM conversations WHERE id="+p,(cid,)).fetchone()
    if found:
        conn.execute("UPDATE conversations SET customer_name="+p+", customer_email="+p+", updated_at="+("NOW()" if pg else "datetime('now')")+" WHERE id="+p,(name or None,email or None,cid))
    elif pg: conn.execute("INSERT INTO conversations(id,customer_name,customer_email) VALUES(%s,%s,%s)",(cid,name or None,email or None))
    else: conn.execute("INSERT INTO conversations(id,customer_name,customer_email,created_at,updated_at) VALUES(?,?,?,?,?)",(cid,name or None,email or None,time.strftime("%Y-%m-%d %H:%M:%S"),time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close(); return cid

def list_messages(conversation_id, limit=100):
    limit=min(max(int(limit),1),100); conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    rs=conn.execute(f"SELECT * FROM messages WHERE conversation_id={p} ORDER BY id ASC LIMIT {p}",(conversation_id,limit)).fetchall()
    conn.close(); return [row(x) for x in rs]

def answer_question(question, name="", email="", conversation_id=""):
    question=redact_sensitive((question or "").strip())[:MAX_MESSAGE_CHARS]
    if not question: return {"answer":"Напишите вопрос одним сообщением.","status":"needs_clarification"}
    conversation_id=ensure_conversation(name,email,conversation_id)
    save_message(conversation_id,"user",question,"received")
    reason=risky(question)
    if reason:
        answer="Я передал обращение специалисту, чтобы не дать неточный или небезопасный ответ. Не отправляйте пароли и полные реквизиты карты."
        ticket_id=create_ticket(question,answer,"escalated",reason,name,email)
        save_message(conversation_id,"assistant",answer,"escalated",ticket_id)
        return {"answer":answer,"status":"escalated","ticket_id":ticket_id,"conversation_id":conversation_id}
    answer,topic,must_escalate,source=local_answer(question)
    if answer and must_escalate:
        ticket_id=create_ticket(question,answer,"escalated",topic,name,email)
        save_message(conversation_id,"assistant",answer,"escalated",ticket_id)
        return {"answer":answer,"status":"escalated","ticket_id":ticket_id,"conversation_id":conversation_id,"source":source}
    ai=ai_answer(question)
    if ai:
        save_message(conversation_id,"assistant",ai,"answered")
        return {"answer":ai,"status":"answered","conversation_id":conversation_id,"source":source or "AI"}
    if answer:
        save_message(conversation_id,"assistant",answer,"answered")
        return {"answer":answer,"status":"answered","conversation_id":conversation_id,"source":source}
    fallback="Я пока не нашёл точного ответа. Уточните вопрос или передам его менеджеру."
    ticket_id=create_ticket(question,fallback,"needs_clarification","недостаточно данных",name,email)
    save_message(conversation_id,"assistant",fallback,"needs_clarification",ticket_id)
    return {"answer":fallback,"status":"needs_clarification","ticket_id":ticket_id,"conversation_id":conversation_id}

def row(r):
    return dict(r)

def list_tickets(status=None, priority=None, search=None, assignee=None, unassigned=False, limit=100):
    if status is not None and status not in TICKET_STATUSES:
        raise ValueError("invalid ticket status")
    if priority is not None and priority not in TICKET_PRIORITIES:
        raise ValueError("invalid ticket priority")
    search=str(search or "").strip()[:120]
    limit=min(max(int(limit),1),100)
    conn=db(); clauses=[]; vals=[]
    if status:
        clauses.append("status="+("%s" if is_pg(conn) else "?")); vals.append(status)
    if priority:
        clauses.append("priority="+("%s" if is_pg(conn) else "?")); vals.append(priority)
    if unassigned:
        clauses.append("(assignee IS NULL OR assignee='')")
    elif assignee:
        clauses.append("assignee="+("%s" if is_pg(conn) else "?")); vals.append(str(assignee).strip().lower()[:254])
    if search:
        term="%"+search+"%"
        op="%s" if is_pg(conn) else "?"
        clauses.append("(" + " OR ".join(f"{field} LIKE {op}" for field in ("question","customer_name","customer_email","assignee")) + ")")
        vals.extend([term]*4)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    order="ORDER BY CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, id DESC"
    placeholder="%s" if is_pg(conn) else "?"
    vals.append(limit)
    rs=conn.execute(f"SELECT * FROM tickets{where} {order} LIMIT {placeholder}",tuple(vals)).fetchall()
    conn.close(); return [row(x) for x in rs]

TICKET_STATUSES={"answered","escalated","needs_clarification","open","resolved"}
TICKET_PRIORITIES={"low","normal","high","urgent"}

def get_ticket(tid):
    conn=db()
    if is_pg(conn):
        r=conn.execute("SELECT * FROM tickets WHERE id=%s",(tid,)).fetchone()
    else:
        r=conn.execute("SELECT * FROM tickets WHERE id=?",(tid,)).fetchone()
    conn.close()
    return row(r) if r else None

def update_ticket(tid, fields, actor="system"):
    allowed={"status","priority","assignee","customer_name","customer_email"}
    fields={k:v for k,v in fields.items() if k in allowed}
    if not fields: return None
    if "status" in fields and fields["status"] not in TICKET_STATUSES: raise ValueError("invalid ticket status")
    if "priority" in fields and fields["priority"] not in TICKET_PRIORITIES: raise ValueError("invalid ticket priority")
    if "customer_email" in fields and fields["customer_email"]:
        email=str(fields["customer_email"]).strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): raise ValueError("invalid customer email")
        fields["customer_email"]=email
    if "customer_name" in fields: fields["customer_name"]=str(fields["customer_name"])[:120]
    if "assignee" in fields:
        fields["assignee"]=str(fields["assignee"]).strip().lower()[:254]
        if fields["assignee"]:
            check=db()
            try:
                exists=check.execute("SELECT email FROM operators WHERE email="+("%s" if is_pg(check) else "?"),(fields["assignee"],)).fetchone()
            finally:
                check.close()
            if not exists: raise ValueError("assignee must be an existing operator email")
    conn=db(); pg=is_pg(conn)
    ticket=conn.execute("SELECT status,priority,assignee FROM tickets WHERE id="+("%s" if pg else "?"),(tid,)).fetchone()
    if not ticket:
        conn.close()
        return False
    before=dict(ticket)
    sets=[]; vals=[]
    for k,v in fields.items(): sets.append(f"{k}={'%s' if pg else '?'}"); vals.append(v)
    sets.append("updated_at=NOW()" if pg else "updated_at=datetime('now')")
    if fields.get("status")=="resolved":
        sets.append("resolved_at=NOW()" if pg else "resolved_at=datetime('now')")
    elif "status" in fields:
        sets.append("resolved_at=NULL")
    vals.append(tid)
    q=f"UPDATE tickets SET {', '.join(sets)} WHERE id={'%s' if pg else '?'}"
    conn.execute(q,vals)
    after={k:fields.get(k,before[k]) for k in before}
    changes={k:{"from":before[k],"to":after[k]} for k in before if before[k]!=after[k]}
    if changes:
        details=json.dumps(changes,ensure_ascii=False)
        if pg:
            conn.execute("INSERT INTO ticket_events(ticket_id,actor,action,details) VALUES(%s,%s,%s,%s)",(tid,str(actor)[:160],"ticket.updated",details))
        else:
            conn.execute("INSERT INTO ticket_events(ticket_id,actor,action,details,created_at) VALUES(?,?,?,?,datetime('now'))",(tid,str(actor)[:160],"ticket.updated",details))
    if changes:
        if after.get("assignee"):
            create_notification("assignment","Вам назначено обращение",f"Обращение #{tid}",tid,str(after["assignee"]).strip().lower(),conn=conn)
        if after.get("status") in ("escalated","open"):
            create_notification("ticket","Обновлено обращение",f"Обращение #{tid}: статус {after.get('status')}",tid,conn=conn)
    conn.commit(); conn.close()
    return True

def list_ticket_events(tid, limit=100):
    limit=min(max(int(limit),1),100)
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    rs=conn.execute(f"SELECT * FROM ticket_events WHERE ticket_id={p} ORDER BY id DESC LIMIT {p}",(tid,limit)).fetchall()
    conn.close(); return [row(x) for x in rs]

def list_customers(search=None, limit=200):
    search=str(search or "").strip()[:120]
    limit=min(max(int(limit),1),200)
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    where=""
    vals=[]
    if search:
        term="%"+search+"%"
        where=" WHERE customer_email LIKE "+p+" OR customer_name LIKE "+p
        vals.extend([term,term])
    rs=conn.execute(f"SELECT * FROM tickets{where} ORDER BY created_at DESC LIMIT {p}",tuple(vals+[5000])).fetchall()
    tickets=[row(x) for x in rs]
    leads=[]
    try:
        lrs=conn.execute("SELECT id,email,name,company,status,created_at FROM leads ORDER BY created_at DESC LIMIT 5000").fetchall()
        leads=[row(x) for x in lrs]
    except Exception:
        leads=[]
    conn.close()
    groups={}
    for t in tickets:
        email=(t.get("customer_email") or "").strip().lower()
        name=(t.get("customer_name") or "").strip()
        key=email or name.lower()
        if not key:
            continue
        if key not in groups:
            groups[key]={"key":key,"name":name or "Клиент","email":email or "",
                         "total_tickets":0,"open_tickets":0,"escalated_tickets":0,
                         "last_interaction":t.get("created_at"),"tickets":[],"leads":[]}
        g=groups[key]
        g["name"]=name or g["name"]
        g["email"]=email or g["email"]
        g["total_tickets"]+=1
        if t.get("status") in ("escalated","needs_clarification","open"): g["open_tickets"]+=1
        if t.get("status")=="escalated": g["escalated_tickets"]+=1
        g["tickets"].append(t)
    for l in leads:
        email=(l.get("email") or "").strip().lower()
        if email and email in groups:
            groups[email]["leads"].append(l)
    out=list(groups.values())
    out.sort(key=lambda x: str(x.get("last_interaction") or ""), reverse=True)
    return out[:limit]


def _money_amount(value):
    from decimal import Decimal, InvalidOperation
    try:
        amount=Decimal(str(value)).quantize(Decimal("0.000001"))
    except (InvalidOperation, ValueError):
        raise ValueError("invalid amount")
    if amount <= 0 or amount > Decimal("1000000000000"):
        raise ValueError("amount must be greater than 0 and within limits")
    return format(amount, "f")

def init_finance_db(conn):
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS money_accounts(
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, currency TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(name,currency))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS money_transactions(
          id BIGSERIAL PRIMARY KEY, account_id BIGINT NOT NULL, kind TEXT NOT NULL,
          amount TEXT NOT NULL, description TEXT, reference TEXT,
          created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          CHECK (kind IN ('credit','debit')))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS crypto_wallets(
          id BIGSERIAL PRIMARY KEY, label TEXT NOT NULL, network TEXT NOT NULL,
          address TEXT NOT NULL, asset TEXT NOT NULL DEFAULT 'USDT',
          created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(network,address,asset))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS crypto_transactions(
          id BIGSERIAL PRIMARY KEY, wallet_id BIGINT NOT NULL, tx_hash TEXT,
          direction TEXT NOT NULL, asset TEXT NOT NULL, amount TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'recorded', note TEXT,
          created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          CHECK (direction IN ('in','out')))""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS money_accounts(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, currency TEXT NOT NULL,
          created_at TEXT NOT NULL, UNIQUE(name,currency))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS money_transactions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, kind TEXT NOT NULL,
          amount TEXT NOT NULL, description TEXT, reference TEXT,
          created_by TEXT NOT NULL, created_at TEXT NOT NULL,
          CHECK (kind IN ('credit','debit')))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS crypto_wallets(
          id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, network TEXT NOT NULL,
          address TEXT NOT NULL, asset TEXT NOT NULL DEFAULT 'USDT',
          created_by TEXT NOT NULL, created_at TEXT NOT NULL,
          UNIQUE(network,address,asset))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS crypto_transactions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, wallet_id INTEGER NOT NULL, tx_hash TEXT,
          direction TEXT NOT NULL, asset TEXT NOT NULL, amount TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'recorded', note TEXT,
          created_by TEXT NOT NULL, created_at TEXT NOT NULL,
          CHECK (direction IN ('in','out')))""")

def list_money_accounts():
    from decimal import Decimal
    conn=db(); pg=is_pg(conn); rs=conn.execute("SELECT * FROM money_accounts ORDER BY id").fetchall()
    result=[]
    for a in rs:
        p="%s" if pg else "?"
        txs=conn.execute("SELECT kind,amount FROM money_transactions WHERE account_id="+p,(a["id"],)).fetchall()
        balance=Decimal("0")
        for t in txs:
            value=Decimal(str(t["amount"]))
            balance += value if t["kind"]=="credit" else -value
        item=row(a); item["balance"]=format(balance,"f"); result.append(item)
    conn.close(); return result

def create_money_account(name,currency="EUR"):
    name=str(name or "").strip()[:120]
    currency=str(currency or "").strip().upper()[:12]
    if not name or not re.fullmatch(r"[A-Z0-9]{3,12}",currency): raise ValueError("invalid account or currency")
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    try:
        if pg:
            conn.execute("INSERT INTO money_accounts(name,currency) VALUES(%s,%s)",(name,currency))
        else:
            conn.execute("INSERT INTO money_accounts(name,currency,created_at) VALUES(?,?,datetime('now'))",(name,currency))
        conn.commit()
    except Exception as exc:
        conn.close(); raise ValueError("account already exists") from exc
    conn.close(); return True

def record_money_transaction(account_id,kind,amount,description="",reference="",created_by="system"):
    if kind not in {"credit","debit"}: raise ValueError("invalid transaction type")
    amount=_money_amount(amount); description=str(description or "").strip()[:500]; reference=str(reference or "").strip()[:160]
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    account=conn.execute("SELECT id FROM money_accounts WHERE id="+p,(int(account_id),)).fetchone()
    if not account: conn.close(); raise ValueError("account not found")
    if kind=="debit":
        from decimal import Decimal
        txs=conn.execute("SELECT kind,amount FROM money_transactions WHERE account_id="+p,(int(account_id),)).fetchall()
        balance=sum((Decimal(str(t["amount"])) if t["kind"]=="credit" else -Decimal(str(t["amount"])) for t in txs),Decimal("0"))
        if balance < Decimal(amount): conn.close(); raise ValueError("insufficient account balance")
    if pg:
        conn.execute("INSERT INTO money_transactions(account_id,kind,amount,description,reference,created_by) VALUES(%s,%s,%s,%s,%s,%s)",(int(account_id),kind,amount,description or None,reference or None,created_by))
    else:
        conn.execute("INSERT INTO money_transactions(account_id,kind,amount,description,reference,created_by,created_at) VALUES(?,?,?,?,?,?,datetime('now'))",(int(account_id),kind,amount,description or None,reference or None,created_by))
    conn.commit(); conn.close(); return True

def list_money_transactions(account_id=None,limit=100):
    limit=min(max(int(limit),1),100); conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    if account_id:
        rs=conn.execute(f"SELECT * FROM money_transactions WHERE account_id={p} ORDER BY id DESC LIMIT {limit}",(int(account_id),)).fetchall()
    else:
        rs=conn.execute(f"SELECT * FROM money_transactions ORDER BY id DESC LIMIT {limit}").fetchall()
    conn.close(); return [row(x) for x in rs]

def _wallet_address_ok(network,address):
    address=str(address or "").strip()
    if network=="ethereum" or network=="bsc":
        return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}",address))
    if network=="tron":
        return bool(re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}",address))
    raise ValueError("unsupported network; use ethereum, bsc or tron")

def list_crypto_wallets():
    conn=db(); rs=conn.execute("SELECT * FROM crypto_wallets ORDER BY id DESC").fetchall(); conn.close(); return [row(x) for x in rs]

def add_crypto_wallet(label,network,address,created_by):
    label=str(label or "").strip()[:120]; network=str(network or "").strip().lower(); address=str(address or "").strip()
    if not label: raise ValueError("wallet label is required")
    if network not in {"ethereum","bsc","tron"}: raise ValueError("unsupported network")
    if not _wallet_address_ok(network,address): raise ValueError("invalid wallet address")
    conn=db(); pg=is_pg(conn)
    try:
        if pg: conn.execute("INSERT INTO crypto_wallets(label,network,address,created_by) VALUES(%s,%s,%s,%s)",(label,network,address,created_by))
        else: conn.execute("INSERT INTO crypto_wallets(label,network,address,created_by,created_at) VALUES(?,?,?,?,datetime('now'))",(label,network,address,created_by))
        conn.commit()
    except Exception as exc:
        conn.close(); raise ValueError("wallet already exists") from exc
    conn.close(); return True

def list_crypto_transactions(wallet_id=None,limit=100):
    limit=min(max(int(limit),1),100); conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    if wallet_id:
        rs=conn.execute(f"SELECT * FROM crypto_transactions WHERE wallet_id={p} ORDER BY id DESC LIMIT {limit}",(int(wallet_id),)).fetchall()
    else:
        rs=conn.execute(f"SELECT * FROM crypto_transactions ORDER BY id DESC LIMIT {limit}").fetchall()
    conn.close(); return [row(x) for x in rs]

def record_crypto_transaction(wallet_id,direction,amount,tx_hash="",note="",created_by="system"):
    if direction not in {"in","out"}: raise ValueError("invalid crypto direction")
    amount=_money_amount(amount); tx_hash=str(tx_hash or "").strip()[:128]; note=str(note or "").strip()[:500]
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    wallet=conn.execute("SELECT id FROM crypto_wallets WHERE id="+p,(int(wallet_id),)).fetchone()
    if not wallet: conn.close(); raise ValueError("wallet not found")
    if pg: conn.execute("INSERT INTO crypto_transactions(wallet_id,direction,asset,amount,tx_hash,note,created_by) VALUES(%s,%s,'USDT',%s,%s,%s,%s)",(int(wallet_id),direction,amount,tx_hash or None,note or None,created_by))
    else: conn.execute("INSERT INTO crypto_transactions(wallet_id,direction,asset,amount,tx_hash,note,created_by,created_at) VALUES(?,?,?,?,?,?,?,datetime('now'))",(int(wallet_id),direction,"USDT",amount,tx_hash or None,note or None,created_by))
    conn.commit(); conn.close(); return True

def crypto_wallet_balances():
    from decimal import Decimal
    wallets=list_crypto_wallets()
    for w in wallets:
        txs=list_crypto_transactions(w["id"])
        balance=sum((Decimal(str(t["amount"])) if t["direction"]=="in" else -Decimal(str(t["amount"])) for t in txs),Decimal("0"))
        w["balance"]=format(balance,"f")
    return wallets

def stats():
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    def scalar(sql, params=()):
        return int(conn.execute(sql,tuple(params)).fetchone()["n"])
    total=scalar("SELECT COUNT(*) AS n FROM tickets")
    answered=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status="+p,("answered",))
    escalated=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status="+p,("escalated",))
    open_count=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status IN ('escalated','needs_clarification','open')")
    resolved=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status="+p,("resolved",))
    conversations=scalar("SELECT COUNT(*) AS n FROM conversations")
    messages=scalar("SELECT COUNT(*) AS n FROM messages")
    operators=scalar("SELECT COUNT(*) AS n FROM operators")
    unassigned=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status IN ('escalated','needs_clarification','open') AND (assignee IS NULL OR assignee='')")
    unread=scalar("SELECT COUNT(*) AS n FROM notifications WHERE read_at IS NULL")
    try: leads=scalar("SELECT COUNT(*) AS n FROM leads")
    except Exception: leads=0
    conn.close()
    return {"total":total,"answered":answered,"escalated":escalated,"open":open_count,
            "resolved":resolved,"conversations":conversations,"messages":messages,
            "operators":operators,"unassigned":unassigned,"leads":leads,"unread_notifications":unread}

def create_notification(kind,title,body="",ticket_id=None,recipient=None,conn=None):
    """Create a notification. Broadcasts are materialized per operator so read state is private."""
    own=conn is None
    if own: conn=db()
    pg=is_pg(conn)
    recipients=[str(recipient).strip().lower()] if recipient else []
    if not recipients:
        rs=conn.execute("SELECT email FROM operators")
        recipients=[str(x["email"]).strip().lower() for x in rs.fetchall()]
    if not recipients:
        recipients=[None]
    for target in recipients:
        if pg:
            conn.execute("INSERT INTO notifications(recipient,kind,title,body,ticket_id) VALUES(%s,%s,%s,%s,%s)",(target,kind,str(title)[:200],str(body)[:2000],ticket_id))
        else:
            conn.execute("INSERT INTO notifications(recipient,kind,title,body,ticket_id,created_at) VALUES(?,?,?,?,?,datetime('now'))",(target,kind,str(title)[:200],str(body)[:2000],ticket_id))
    if own: conn.commit(); conn.close()

def list_notifications(recipient,limit=50):
    recipient=str(recipient or "").strip().lower()
    limit=min(max(int(limit),1),100); conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    rs=conn.execute(f"SELECT * FROM notifications WHERE recipient={p} ORDER BY id DESC LIMIT {limit}",(recipient,)).fetchall()
    conn.close(); return [row(x) for x in rs]

def mark_notification_read(notification_id,recipient):
    recipient=str(recipient or "").strip().lower()
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    rs=conn.execute("UPDATE notifications SET read_at="+("NOW()" if pg else "datetime('now')")+" WHERE id="+p+" AND recipient="+p,(notification_id,recipient))
    conn.commit(); changed=rs.rowcount; conn.close(); return bool(changed)

def make_token(email,role):
    t=secrets.token_urlsafe(32); SESSIONS[t]={"expires":time.time()+TOKEN_TTL,"email":email,"role":role}; return t
def session_token(h):
    token=(h.get("Authorization") or "").replace("Bearer ","").strip()
    if token: return token
    cookie=h.get("Cookie","")
    for part in cookie.split(";"):
        k,v=(part.strip().split("=",1)+[""])[:2]
        if k==SESSION_COOKIE_NAME: return v
    return ""

def session(h):
    token=session_token(h)
    s=SESSIONS.get(token)
    if s and s["expires"]>time.time(): return s
    if token: SESSIONS.pop(token,None)
    return None

def auth(h,permission="read"):
    s=session(h)
    return s if s and permission in ROLE_PERMISSIONS.get(s["role"],set()) else None

class Handler(BaseHTTPRequestHandler):
    def _origin(self):
        allowed={x.strip() for x in os.getenv("CORS_ORIGINS","").split(",") if x.strip()}
        origin=self.headers.get("Origin")
        return origin if origin and origin in allowed else None
    def _csrf_ok(self):
        """Allow same-origin browser mutations and explicitly configured CORS origins."""
        origin=self.headers.get("Origin")
        if origin:
            allowed={x.strip() for x in os.getenv("CORS_ORIGINS","").split(",") if x.strip()}
            if origin in allowed:
                return True
            try:
                parsed=urlparse(origin)
                return parsed.scheme in {"http","https"} and parsed.netloc == self.headers.get("Host","")
            except Exception:
                return False
        referer=self.headers.get("Referer")
        if referer:
            try:
                return urlparse(referer).netloc == self.headers.get("Host","")
            except Exception:
                return False
        return not SECURE_COOKIES
    def _require_csrf(self):
        if self._csrf_ok():
            return True
        self.send_json({"error":"cross-site request blocked"},403)
        return False
    def send_json(self,payload,status=200):
        body=json.dumps(payload,ensure_ascii=False,default=str).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","no-referrer")
        self.send_header("Permissions-Policy","geolocation=(), camera=(), microphone=()")
        if SECURE_COOKIES:
            self.send_header("Strict-Transport-Security","max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
        if getattr(self,"_clear_session_cookie",False):
            self.send_header("Set-Cookie",clear_session_cookie())
        elif getattr(self,"_set_session_cookie",""):
            self.send_header("Set-Cookie",session_cookie(self._set_session_cookie))
        self.end_headers(); self.wfile.write(body)
    def body(self):
        n=int(self.headers.get("Content-Length","0"))
        if n>1_000_000: raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}")
    def require(self,permission="read"):
        s=auth(self.headers,permission)
        if not s:
            self.send_json({"error":"authentication required"},401); return None
        return s
    def do_OPTIONS(self):
        self.send_response(204)
        origin=self._origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin",origin)
            self.send_header("Vary","Origin")
        self.send_header("Access-Control-Allow-Headers","Content-Type, Authorization"); self.send_header("Access-Control-Allow-Methods","GET,POST,PATCH,DELETE,OPTIONS"); self.end_headers()
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/health":
            return self.send_json({"ok":True,"service":"SupportPilot","version":"2.0","database":"postgres" if DATABASE_URL else "sqlite-fallback","ai":bool(AI_API_KEY),"auth":bool(ADMIN_PASSWORD or OPERATORS_JSON)})
        if path=="/api/me":
            s=self.require()
            if not s: return
            return self.send_json({"user":{"email":s["email"],"role":s["role"]}})
        if path=="/api/operators":
            if not self.require("manage"): return
            return self.send_json({"operators":list_operators()})
        if path.startswith("/api/operators/"):
            if not self.require("manage"): return
            email=__import__("urllib.parse",fromlist=["unquote"]).unquote(path.rsplit("/",1)[1])
            op=next((x for x in list_operators() if x["email"]==email.lower()),None)
            return self.send_json({"operator":op} if op else {"error":"operator not found"},200 if op else 404)
        if path=="/api/kb":
            return self.send_json({"items":KB,"count":len(KB)})
        if path.startswith("/api/conversations/") and path.endswith("/messages"):
            if not self.require(): return
            conversation_id=path.split("/")[3]
            return self.send_json({"conversation_id":conversation_id,"messages":list_messages(conversation_id)})
        if path=="/api/leads":
            if not self.require(): return
            from lead_pipeline import list_leads
            params=parse_qs(urlparse(self.path).query)
            status=params.get("status",[None])[0]
            search=params.get("q",[""])[0]
            if status:
                from lead_pipeline import LEAD_STATUSES
                if status not in LEAD_STATUSES:
                    return self.send_json({"error":"invalid lead status"},400)
            return self.send_json({"leads":list_leads(status=status,search=search)})
        if path.startswith("/api/leads/"):
            if not self.require(): return
            from lead_pipeline import get_lead, list_lead_events
            lead_id=path.rsplit("/",1)[1]
            lead=get_lead(lead_id)
            return self.send_json({"lead":lead,"events":list_lead_events(lead_id)} if lead else {"error":"lead not found"},200 if lead else 404)
        if path=="/api/tickets":
            if not self.require(): return
            params=parse_qs(urlparse(self.path).query)
            status=params.get("status",[None])[0]
            priority=params.get("priority",[None])[0]
            search=params.get("q",[""])[0]
            assignee=params.get("assignee",[""])[0]
            unassigned=params.get("unassigned",["0"])[0] in ("1","true","yes")
            if assignee=="__unassigned__":
                assignee=""
                unassigned=True
            try:
                tickets=list_tickets(status=status,priority=priority,search=search,assignee=assignee,unassigned=unassigned)
            except ValueError as e:
                return self.send_json({"error":str(e)},400)
            return self.send_json({"tickets":tickets})
        if path.startswith("/api/tickets/"):
            if not self.require(): return
            try: tid=int(path.rsplit("/",1)[1])
            except ValueError: return self.send_json({"error":"invalid ticket id"},400)
            ticket=get_ticket(tid)
            if not ticket: return self.send_json({"error":"ticket not found"},404)
            return self.send_json({"ticket":ticket,"events":list_ticket_events(tid)})
        if path=="/api/customers":
            if not self.require(): return
            search=parse_qs(urlparse(self.path).query).get("q",[""])[0]
            return self.send_json({"customers":list_customers(search=search)})
        if path=="/api/stats":
            if not self.require(): return
            return self.send_json(stats())
        if path=="/api/finance/accounts":
            if not self.require(): return
            return self.send_json({"accounts":list_money_accounts(),"transactions":list_money_transactions()})
        if path=="/api/finance/transactions":
            if not self.require(): return
            account_id=parse_qs(urlparse(self.path).query).get("account_id",[None])[0]
            return self.send_json({"transactions":list_money_transactions(account_id)})
        if path=="/api/crypto/wallets":
            if not self.require(): return
            return self.send_json({"wallets":crypto_wallet_balances(),"transactions":list_crypto_transactions()})
        if path=="/api/crypto/transactions":
            if not self.require(): return
            wallet_id=parse_qs(urlparse(self.path).query).get("wallet_id",[None])[0]
            return self.send_json({"transactions":list_crypto_transactions(wallet_id)})
        if path=="/api/notifications":
            s=self.require()
            if not s: return
            items=list_notifications(s["email"])
            return self.send_json({"notifications":items,"unread":sum(1 for x in items if not x.get("read_at"))})
        if path in ("/","/index.html"):
            f=BASE/"web"/"index.html"; b=f.read_bytes()
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY"); self.send_header("Referrer-Policy","no-referrer"); self.send_header("Permissions-Policy","geolocation=(), camera=(), microphone=()");
            if SECURE_COOKIES: self.send_header("Strict-Transport-Security","max-age=31536000; includeSubDomains")
            self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'") ; self.end_headers(); self.wfile.write(b); return
        self.send_json({"error":"not found"},404)
    def do_POST(self):
        self._set_session_cookie=""
        path=urlparse(self.path).path
        if path not in ("/api/login","/api/chat","/api/leads") and not self._require_csrf():
            return
        try: p=self.body()
        except ValueError as e: return self.send_json({"error":str(e)},413 if "large" in str(e) else 400)
        if path=="/api/login":
            email=str(p.get("email","")).strip(); password=str(p.get("password",""))
            now=time.time(); client=self.client_address[0]
            recent=[t for t in LOGIN_RATE.get(client,[]) if now-t < LOGIN_RATE_WINDOW]
            if len(recent) >= LOGIN_RATE_MAX:
                LOGIN_RATE[client]=recent
                return self.send_json({"ok":False,"error":"Слишком много попыток входа. Попробуйте позже."},429)
            LOGIN_RATE[client]=recent+[now]
            conn=db()
            op=conn.execute("SELECT email,password_hash,role FROM operators WHERE email="+("%s" if is_pg(conn) else "?"),(email.lower(),)).fetchone()
            conn.close()
            if op and verify_password(password,op["password_hash"]):
                LOGIN_RATE.pop(client,None)
                self._set_session_cookie=make_token(op["email"],op["role"])
                return self.send_json({"ok":True,"user":{"email":op["email"],"role":op["role"]}})
            if not ADMIN_PASSWORD and not OPERATORS_JSON:
                return self.send_json({"ok":False,"error":"No operator credentials are configured on the server"},503)
            return self.send_json({"ok":False,"error":"Неверный email или пароль"},401)
        if path=="/api/operators":
            s=self.require("manage")
            if not s: return
            try:
                p=self.body(); create_operator(p.get("email"),p.get("password"),p.get("role"))
            except ValueError as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":True},201)
        if path=="/api/finance/accounts":
            s=self.require("write")
            if not s: return
            try: create_money_account(p.get("name"),p.get("currency","EUR"))
            except ValueError as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":True},201)
        if path=="/api/finance/transactions":
            s=self.require("write")
            if not s: return
            try: record_money_transaction(p.get("account_id"),p.get("kind"),p.get("amount"),p.get("description"),p.get("reference"),s["email"])
            except (ValueError,TypeError) as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":True},201)
        if path=="/api/crypto/wallets":
            s=self.require("write")
            if not s: return
            try: add_crypto_wallet(p.get("label"),p.get("network"),p.get("address"),s["email"])
            except ValueError as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":True},201)
        if path=="/api/crypto/transactions":
            s=self.require("write")
            if not s: return
            try: record_crypto_transaction(p.get("wallet_id"),p.get("direction"),p.get("amount"),p.get("tx_hash"),p.get("note"),s["email"])
            except (ValueError,TypeError) as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":True},201)
        if path=="/api/logout":
            token=session_token(self.headers); SESSIONS.pop(token,None)
            self._clear_session_cookie=True
            self._set_session_cookie=""
            return self.send_json({"ok":True})
        if path=="/api/chat":
            now=time.time()
            client=self.client_address[0]
            recent=[t for t in CHAT_RATE.get(client,[]) if now-t < CHAT_RATE_WINDOW]
            if len(recent) >= CHAT_RATE_MAX:
                CHAT_RATE[client]=recent
                return self.send_json({"error":"Слишком много сообщений. Попробуйте через минуту."},429)
            CHAT_RATE[client]=recent+[now]
            result=answer_question(p.get("message",""),p.get("name",""),p.get("email",""),p.get("conversation_id","")); return self.send_json(result)
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
    def do_DELETE(self):
        path=urlparse(self.path).path
        if not self._require_csrf():
            return
        if path.startswith("/api/operators/"):
            if not self.require("manage"): return
            from urllib.parse import unquote
            email=unquote(path.rsplit("/",1)[1])
            try: ok=delete_operator(email)
            except ValueError as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":bool(ok)},200 if ok else 404)
        self.send_json({"error":"not found"},404)
    def do_PATCH(self):
        path=urlparse(self.path).path
        if not self._require_csrf():
            return
        if path.startswith("/api/notifications/") and path.endswith("/read"):
            s=self.require("write")
            if not s: return
            try: nid=int(path.split("/")[3])
            except ValueError: return self.send_json({"error":"invalid notification id"},400)
            return self.send_json({"ok":mark_notification_read(nid,s["email"])})

        if path.startswith("/api/leads/"):
            s=self.require("write")
            if not s: return
            try:
                from lead_pipeline import update_lead
                lead_id=path.rsplit("/",1)[1]; ok=update_lead(lead_id,self.body(),actor=s["email"])
            except ValueError as e: return self.send_json({"error":str(e)},400)
            except Exception:
                return self.send_json({"error":"lead update failed"},500)
            if not ok:
                return self.send_json({"error":"lead not found"},404)
            return self.send_json({"ok":True})
        if path.startswith("/api/tickets/"):
            s=self.require("write")
            if not s: return
            try:
                tid=int(path.rsplit("/",1)[1])
                ok=update_ticket(tid,self.body(),actor=s["email"])
            except ValueError as e: return self.send_json({"error":str(e)},400)
            except Exception as e: return self.send_json({"error":"ticket update failed"},500)
            return self.send_json({"ok":bool(ok)})
        self.send_json({"error":"not found"},404)
    def log_message(self,fmt,*args): print("WEB",fmt%args,flush=True)

if __name__=="__main__":
    init_db(); ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
