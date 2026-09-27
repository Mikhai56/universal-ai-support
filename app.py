#!/usr/bin/env python3
"""SupportPilot — production-minded AI customer support app."""
import hashlib, html, hmac, json, os, re, secrets, sqlite3, time, urllib.request, urllib.error
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

def row(value):
    return dict(value)

def init_db():
    conn = db()
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS tickets(
          id BIGSERIAL PRIMARY KEY, chat_id TEXT NOT NULL, username TEXT, question TEXT NOT NULL,
          answer TEXT NOT NULL, status TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'normal',
          reason TEXT, assignee TEXT, customer_email TEXT, customer_name TEXT, company_id TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          resolved_at TIMESTAMPTZ)""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS tickets(
          id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT NOT NULL, username TEXT,
          question TEXT NOT NULL, answer TEXT NOT NULL, status TEXT NOT NULL,
          priority TEXT NOT NULL DEFAULT 'normal', reason TEXT, assignee TEXT,
          customer_email TEXT, customer_name TEXT, created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL, resolved_at TEXT, company_id TEXT)""")
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS ticket_events(
          id BIGSERIAL PRIMARY KEY, ticket_id BIGINT NOT NULL, company_id TEXT,
          actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS company_id TEXT")
        conn.execute("ALTER TABLE ticket_events ADD COLUMN IF NOT EXISTS company_id TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_company_id ON tickets(company_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_events_company_id ON ticket_events(company_id)")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS ticket_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, company_id TEXT,
          actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL)""")
        tc={r["name"] for r in conn.execute("PRAGMA table_info(tickets)").fetchall()}
        if "company_id" not in tc: conn.execute("ALTER TABLE tickets ADD COLUMN company_id TEXT")
        ec={r["name"] for r in conn.execute("PRAGMA table_info(ticket_events)").fetchall()}
        if "company_id" not in ec: conn.execute("ALTER TABLE ticket_events ADD COLUMN company_id TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_company_id ON tickets(company_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_events_company_id ON ticket_events(company_id)")
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
          id TEXT PRIMARY KEY, company_id TEXT, customer_name TEXT, customer_email TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("""CREATE TABLE IF NOT EXISTS messages(
          id BIGSERIAL PRIMARY KEY, conversation_id TEXT NOT NULL, role TEXT NOT NULL,
          content TEXT NOT NULL, status TEXT, ticket_id BIGINT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS conversations(
          id TEXT PRIMARY KEY, company_id TEXT, customer_name TEXT, customer_email TEXT,
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
    init_commercial_db(conn)
    conn.commit(); conn.close()

def words(text):
    stop={"как","какой","какая","какие","что","это","есть","ли","вы","можно","нужно","для","при","по","на","мне","про"}
    return {w for w in re.findall(r"[a-zа-яё0-9]+", text.lower()) if len(w)>2 and w not in stop}

def local_answer(question, company_id=None):
    if company_id is not None:
        tenant=tenant_local_answer(question,company_id)
        if tenant[0] is not None:
            return tenant

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

def create_ticket(question,answer,status,reason="",customer_name="",customer_email="",company_id=None):
    conn=db(); q=redact_sensitive(question); a=redact_sensitive(answer)
    if is_pg(conn):
        cur=conn.execute("""INSERT INTO tickets(chat_id,username,question,answer,status,priority,reason,customer_name,customer_email,company_id)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
          ("web","web-user",q,a,status,"high" if status=="escalated" else "normal",reason,customer_name,customer_email,company_id))
        tid=cur.fetchone()["id"]
    else:
        now=time.strftime("%Y-%m-%d %H:%M:%S")
        cur=conn.execute("""INSERT INTO tickets(chat_id,username,question,answer,status,priority,reason,customer_name,customer_email,company_id,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",("web","web-user",q,a,status,"high" if status=="escalated" else "normal",reason,customer_name,customer_email,company_id,now,now))
        tid=cur.lastrowid
    # Record the creation event so every ticket has a complete audit trail from the first moment.
    if is_pg(conn):
        conn.execute("INSERT INTO ticket_events(ticket_id,company_id,actor,action,details) VALUES(%s,%s,%s,%s,%s)",(tid,company_id,"system","ticket.created",json.dumps({"status":status,"reason":reason or ""},ensure_ascii=False)))
    else:
        conn.execute("INSERT INTO ticket_events(ticket_id,company_id,actor,action,details,created_at) VALUES(?,?,?,?,?,datetime('now'))",(tid,company_id,"system","ticket.created",json.dumps({"status":status,"reason":reason or ""},ensure_ascii=False)))
    if status in ("escalated","needs_clarification"):
        create_notification("ticket","Новое обращение требует внимания",f"Обращение #{tid}: {reason or status}",tid,conn=conn)
    conn.commit(); conn.close(); return tid

def ai_answer(question, company_id=None):

    if not AI_API_KEY: return None
    context=json.dumps(tenant_kb_context(company_id) if company_id is not None else KB,ensure_ascii=False)

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

def ensure_conversation(name="", email="", conversation_id="", company_id=None):
    cid=str(conversation_id or "").strip()
    if not re.fullmatch(r"[a-f0-9]{32}",cid): cid=secrets.token_hex(16)
    name=str(name or "").strip()[:120]; email=str(email or "").strip().lower()[:254]
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    scope=(" AND company_id="+p) if company_id is not None else ""
    scope_vals=[str(company_id)] if company_id is not None else []
    found=conn.execute("SELECT id FROM conversations WHERE id="+p+scope,(cid,*scope_vals)).fetchone()
    if found:
        conn.execute("UPDATE conversations SET customer_name="+p+", customer_email="+p+", updated_at="+("NOW()" if pg else "datetime('now')")+" WHERE id="+p+scope,(name or None,email or None,cid,*scope_vals))
    elif company_id is not None:
        any_found=conn.execute("SELECT id FROM conversations WHERE id="+p,(cid,)).fetchone()
        if any_found: cid=secrets.token_hex(16)
        if pg: conn.execute("INSERT INTO conversations(id,company_id,customer_name,customer_email) VALUES(%s,%s,%s,%s)",(cid,company_id,name or None,email or None))
        else: conn.execute("INSERT INTO conversations(id,company_id,customer_name,customer_email,created_at,updated_at) VALUES(?,?,?,?,?,?)",(cid,company_id,name or None,email or None,time.strftime("%Y-%m-%d %H:%M:%S"),time.strftime("%Y-%m-%d %H:%M:%S")))
    elif pg: conn.execute("INSERT INTO conversations(id,company_id,customer_name,customer_email) VALUES(%s,%s,%s,%s)",(cid,company_id,name or None,email or None))
    else: conn.execute("INSERT INTO conversations(id,company_id,customer_name,customer_email,created_at,updated_at) VALUES(?,?,?,?,?,?)",(cid,company_id,name or None,email or None,time.strftime("%Y-%m-%d %H:%M:%S"),time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close(); return cid

def list_messages(conversation_id, limit=100, company_id=None):
    limit=min(max(int(limit),1),100); conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    if company_id is None:
        rs=conn.execute(f"SELECT m.* FROM messages m WHERE m.conversation_id={p} ORDER BY m.id ASC LIMIT {p}",(conversation_id,limit)).fetchall()
    else:
        rs=conn.execute(f"SELECT m.* FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE m.conversation_id={p} AND c.company_id={p} ORDER BY m.id ASC LIMIT {p}",(conversation_id,str(company_id),limit)).fetchall()
    conn.close(); return [row(x) for x in rs]

def answer_question(question, name="", email="", conversation_id="", company_id=None):
    question=redact_sensitive((question or "").strip())[:MAX_MESSAGE_CHARS]
    if not question: return {"answer":"Напишите вопрос одним сообщением.","status":"needs_clarification"}
    if company_id is not None:
        usage=company_usage(company_id)
        if usage and usage["messages"]["used"] >= usage["messages"]["limit"]:
            return {"answer":"Лимит сообщений текущего тарифа исчерпан. Перейдите на другой тариф в кабинете компании.","status":"limit_reached","usage":usage}
    conversation_id=ensure_conversation(name,email,conversation_id,company_id)
    save_message(conversation_id,"user",question,"received")
    reason=risky(question)
    if reason:
        answer="Я передал обращение специалисту, чтобы не дать неточный или небезопасный ответ. Не отправляйте пароли и полные реквизиты карты."
        ticket_id=create_ticket(question,answer,"escalated",reason,name,email,company_id=company_id)
        save_message(conversation_id,"assistant",answer,"escalated",ticket_id)
        return {"answer":answer,"status":"escalated","ticket_id":ticket_id,"conversation_id":conversation_id}
    answer,topic,must_escalate,source=local_answer(question,company_id)
    if answer and must_escalate:
        ticket_id=create_ticket(question,answer,"escalated",topic,name,email,company_id=company_id)
        save_message(conversation_id,"assistant",answer,"escalated",ticket_id)
        return {"answer":answer,"status":"escalated","ticket_id":ticket_id,"conversation_id":conversation_id,"source":source}
    ai=ai_answer(question,company_id)
    if ai:
        save_message(conversation_id,"assistant",ai,"answered")
        return {"answer":ai,"status":"answered","conversation_id":conversation_id,"source":source or "AI"}
    if answer:
        save_message(conversation_id,"assistant",answer,"answered")
        return {"answer":answer,"status":"answered","conversation_id":conversation_id,"source":source}
    return {"answer":"Я не нашёл точного ответа в базе знаний. Уточните вопрос или передайте обращение менеджеру.","status":"needs_clarification","conversation_id":conversation_id}

def list_tickets(status=None, priority=None, search=None, assignee=None, unassigned=False, limit=100, company_id=None):
    if status is not None and status not in TICKET_STATUSES: raise ValueError("invalid ticket status")
    if priority is not None and priority not in TICKET_PRIORITIES: raise ValueError("invalid ticket priority")
    search=str(search or "").strip()[:120]; limit=min(max(int(limit),1),100)
    conn=db(); clauses=[]; vals=[]; p="%s" if is_pg(conn) else "?"
    if company_id is not None: clauses.append("company_id="+p); vals.append(str(company_id))
    if status: clauses.append("status="+p); vals.append(status)
    if priority: clauses.append("priority="+p); vals.append(priority)
    if unassigned: clauses.append("(assignee IS NULL OR assignee='')")
    elif assignee: clauses.append("assignee="+p); vals.append(str(assignee).strip().lower()[:254])
    if search:
        term="%"+search+"%"
        clauses.append("("+" OR ".join(f"{field} LIKE {p}" for field in ("question","customer_name","customer_email","assignee"))+")")
        vals.extend([term]*4)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    order="ORDER BY CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, id DESC"
    vals.append(limit)
    rs=conn.execute(f"SELECT * FROM tickets{where} {order} LIMIT {p}",tuple(vals)).fetchall()
    conn.close(); return [row(x) for x in rs]

TICKET_STATUSES={"answered","escalated","needs_clarification","open","resolved"}
TICKET_PRIORITIES={"low","normal","high","urgent"}

def get_ticket(tid, company_id=None):
    conn=db(); p="%s" if is_pg(conn) else "?"
    q="SELECT * FROM tickets WHERE id="+p; vals=[tid]
    if company_id is not None: q+=" AND company_id="+p; vals.append(str(company_id))
    r=conn.execute(q,tuple(vals)).fetchone()
    conn.close(); return row(r) if r else None

def update_ticket(tid, fields, actor="system", company_id=None):
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
                pcheck="%s" if is_pg(check) else "?"
                if company_id is not None:
                    exists=check.execute("SELECT email FROM company_members WHERE company_id="+pcheck+" AND lower(email)=lower("+pcheck+") AND status='active' AND role IN ('owner','admin','operator')",(str(company_id),fields["assignee"])).fetchone()
                else:
                    exists=check.execute("SELECT email FROM operators WHERE email="+pcheck,(fields["assignee"],)).fetchone()
            finally: check.close()
            if not exists: raise ValueError("assignee must be an active team operator")
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    scope=(" AND company_id="+p) if company_id is not None else ""; scope_vals=[str(company_id)] if company_id is not None else []
    ticket=conn.execute("SELECT status,priority,assignee FROM tickets WHERE id="+p+scope,(tid,*scope_vals)).fetchone()
    if not ticket: conn.close(); return False
    before=dict(ticket); sets=[]; vals=[]
    for k,v in fields.items(): sets.append(f"{k}={p}"); vals.append(v)
    sets.append("updated_at=NOW()" if pg else "updated_at=datetime('now')")
    if fields.get("status")=="resolved": sets.append("resolved_at=NOW()" if pg else "resolved_at=datetime('now')")
    elif "status" in fields: sets.append("resolved_at=NULL")
    vals.append(tid); vals.extend(scope_vals)
    conn.execute(f"UPDATE tickets SET {', '.join(sets)} WHERE id={p}{scope}",vals)
    after={k:fields.get(k,before[k]) for k in before}; changes={k:{"from":before[k],"to":after[k]} for k in before if before[k]!=after[k]}
    if changes:
        details=json.dumps(changes,ensure_ascii=False)
        if pg: conn.execute("INSERT INTO ticket_events(ticket_id,company_id,actor,action,details) VALUES(%s,%s,%s,%s,%s)",(tid,company_id,str(actor)[:160],"ticket.updated",details))
        else: conn.execute("INSERT INTO ticket_events(ticket_id,company_id,actor,action,details,created_at) VALUES(?,?,?,?,?,datetime('now'))",(tid,company_id,str(actor)[:160],"ticket.updated",details))
        if after.get("assignee"): create_notification("assignment","Вам назначено обращение",f"Обращение #{tid}",tid,str(after["assignee"]).strip().lower(),conn=conn)
        if after.get("status") in ("escalated","open"): create_notification("ticket","Обновлено обращение",f"Обращение #{tid}: статус {after.get('status')}",tid,conn=conn)
    conn.commit(); conn.close(); return True

def list_ticket_events(tid, limit=100, company_id=None):
    limit=min(max(int(limit),1),100); conn=db(); p="%s" if is_pg(conn) else "?"
    if company_id is None:
        rs=conn.execute(f"SELECT * FROM ticket_events WHERE ticket_id={p} ORDER BY id DESC LIMIT {p}",(tid,limit)).fetchall()
    else:
        rs=conn.execute(f"SELECT * FROM ticket_events WHERE ticket_id={p} AND company_id={p} ORDER BY id DESC LIMIT {p}",(tid,str(company_id),limit)).fetchall()
    conn.close(); return [row(x) for x in rs]

def list_customers(search=None, limit=200, company_id=None):
    search=str(search or "").strip()[:120]
    limit=min(max(int(limit),1),200)
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    where=""
    vals=[]
    if company_id is not None:
        where=" WHERE company_id="+p
        vals.append(str(company_id))
    if search:
        term="%"+search+"%"
        prefix=" AND " if where else " WHERE "
        where=where+prefix+"(customer_email LIKE "+p+" OR customer_name LIKE "+p+")"
        vals.extend([term,term])
    rs=conn.execute(f"SELECT * FROM tickets{where} ORDER BY created_at DESC LIMIT {p}",tuple(vals+[5000])).fetchall()
    tickets=[row(x) for x in rs]
    leads=[]
    try:
        lead_sql="SELECT id,email,name,company,status,created_at FROM leads"
        lead_vals=[]
        if company_id is not None:
            lead_sql+=" WHERE company_id="+p; lead_vals.append(str(company_id))
        lead_sql+=" ORDER BY created_at DESC LIMIT 5000"
        lrs=conn.execute(lead_sql,tuple(lead_vals)).fetchall()
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


def get_customer_detail(identifier="", company_id=None):
    identifier=str(identifier or "").strip()
    if not identifier or company_id is None:
        return None
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    ident=identifier.lower()
    # Prefer an exact email match; otherwise use the customer name as the key.
    tickets=conn.execute(
        f"SELECT * FROM tickets WHERE company_id={p} AND (lower(customer_email)={p} OR lower(customer_name)={p}) ORDER BY created_at DESC LIMIT 200",
        (str(company_id),ident,ident)).fetchall()
    ticket_rows=[row(x) for x in tickets]
    email=next((str(x.get("customer_email") or "").strip().lower() for x in ticket_rows if x.get("customer_email")), "")
    name=next((str(x.get("customer_name") or "").strip() for x in ticket_rows if x.get("customer_name")), "")
    leads=[]
    try:
        if email:
            leads=[row(x) for x in conn.execute(f"SELECT * FROM leads WHERE company_id={p} AND lower(email)={p} ORDER BY created_at DESC LIMIT 100",(str(company_id),email)).fetchall()]
        else:
            leads=[row(x) for x in conn.execute(f"SELECT * FROM leads WHERE company_id={p} AND lower(name)={p} ORDER BY created_at DESC LIMIT 100",(str(company_id),ident)).fetchall()]
    except Exception:
        leads=[]
    if not email:
        email=next((str(x.get("email") or "").strip().lower() for x in leads if x.get("email")), "")
    if not name:
        name=next((str(x.get("name") or "").strip() for x in leads if x.get("name")), "")
    conversations=[]
    try:
        if email:
            conv_rows=conn.execute(f"SELECT * FROM conversations WHERE company_id={p} AND lower(customer_email)={p} ORDER BY updated_at DESC LIMIT 30",(str(company_id),email)).fetchall()
        else:
            conv_rows=conn.execute(f"SELECT * FROM conversations WHERE company_id={p} AND lower(customer_name)={p} ORDER BY updated_at DESC LIMIT 30",(str(company_id),ident)).fetchall()
        for c in conv_rows:
            cr=row(c)
            msgs=conn.execute(f"SELECT * FROM messages WHERE conversation_id={p} ORDER BY id ASC LIMIT 100",(cr['id'],)).fetchall()
            cr["messages"]=[row(x) for x in msgs]
            conversations.append(cr)
    except Exception:
        conversations=[]
    conn.close()
    if not ticket_rows and not leads and not conversations:
        return None
    all_dates=[x.get("created_at") for x in ticket_rows+leads+conversations if x.get("created_at")]
    return {
        "key": email or name.lower() or ident,
        "name": name or "Клиент",
        "email": email,
        "tickets": ticket_rows,
        "leads": leads,
        "conversations": conversations,
        "counts": {
            "tickets": len(ticket_rows),
            "open_tickets": sum(1 for x in ticket_rows if x.get("status") in ("open","answered","escalated","needs_clarification")),
            "escalated_tickets": sum(1 for x in ticket_rows if x.get("status")=="escalated"),
            "leads": len(leads),
            "conversations": len(conversations),
            "messages": sum(len(x.get("messages",[])) for x in conversations)
        },
        "last_interaction": max(all_dates, key=str) if all_dates else None
    }

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
        w["balance"]=format(balance,".6f")
    return wallets

def stats(company_id=None):
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    def scalar(sql, params=()):
        return int(conn.execute(sql,tuple(params)).fetchone()["n"])
    scope_t = (" AND company_id="+p) if company_id is not None else ""
    scope_c = (" WHERE company_id="+p) if company_id is not None else ""
    scope_m = (" WHERE conversation_id IN (SELECT id FROM conversations WHERE company_id="+p+")") if company_id is not None else ""
    vals_t = (str(company_id),) if company_id is not None else ()
    total=scalar("SELECT COUNT(*) AS n FROM tickets"+(" WHERE company_id="+p if company_id is not None else ""),vals_t)
    answered=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status="+p+(" AND company_id="+p if company_id is not None else ""),("answered",)+vals_t)
    escalated=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status="+p+(" AND company_id="+p if company_id is not None else ""),("escalated",)+vals_t)
    open_count=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status IN ('escalated','needs_clarification','open')"+(" AND company_id="+p if company_id is not None else ""),vals_t)
    resolved=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status="+p+(" AND company_id="+p if company_id is not None else ""),("resolved",)+vals_t)
    conversations=scalar("SELECT COUNT(*) AS n FROM conversations"+(" WHERE company_id="+p if company_id is not None else ""),vals_t)
    messages=scalar("SELECT COUNT(*) AS n FROM messages"+(" WHERE conversation_id IN (SELECT id FROM conversations WHERE company_id="+p+")" if company_id is not None else ""),vals_t)
    operators=scalar("SELECT COUNT(*) AS n FROM company_members WHERE company_id="+p+" AND status='active'",(str(company_id),)) if company_id is not None else scalar("SELECT COUNT(*) AS n FROM operators")
    unassigned=scalar("SELECT COUNT(*) AS n FROM tickets WHERE status IN ('escalated','needs_clarification','open') AND (assignee IS NULL OR assignee='')"+(" AND company_id="+p if company_id is not None else ""),vals_t)
    unread=scalar("SELECT COUNT(*) AS n FROM notifications WHERE read_at IS NULL")
    try: leads=scalar("SELECT COUNT(*) AS n FROM leads"+(" WHERE company_id="+p if company_id is not None else ""),vals_t)
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


# ---------- Commercial SaaS layer ----------
COMMERCIAL_SESSION_COOKIE = "sp_client_session"
COMMERCIAL_SESSION_TTL = 60 * 60 * 24 * 30
PLANS = {
    "free": {"name":"Free Trial","price_eur":0,"trial_days":14,"messages":200,"operators":1,"channels":1},
    "starter": {"name":"Starter","price_eur":29,"trial_days":0,"messages":3000,"operators":3,"channels":2},
    "business": {"name":"Business","price_eur":79,"trial_days":0,"messages":15000,"operators":10,"channels":5},
    "pro": {"name":"Pro","price_eur":199,"trial_days":0,"messages":50000,"operators":25,"channels":10},
}

def init_commercial_db(conn=None):
    own=False
    if conn is None:
        conn=db(); own=True
    pg=is_pg(conn)
    if pg:
        conn.execute("""CREATE TABLE IF NOT EXISTS companies(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
          owner_email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active', plan TEXT NOT NULL DEFAULT 'free',
          subscription_status TEXT NOT NULL DEFAULT 'trialing',
          trial_ends_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_sessions(
          token TEXT PRIMARY KEY, company_id TEXT NOT NULL, member_id BIGINT, member_email TEXT, member_role TEXT,
          expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_subscriptions(
          id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL, plan TEXT NOT NULL,
          status TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'internal',
          provider_customer_id TEXT, provider_subscription_id TEXT,
          current_period_end TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_members(
          id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL, email TEXT NOT NULL,
          password_hash TEXT, role TEXT NOT NULL DEFAULT 'owner', status TEXT NOT NULL DEFAULT 'active',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(company_id,email),
          CHECK (role IN ('owner','admin','operator','viewer')))""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS companies(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
          owner_email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active', plan TEXT NOT NULL DEFAULT 'free',
          subscription_status TEXT NOT NULL DEFAULT 'trialing',
          trial_ends_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_sessions(
          token TEXT PRIMARY KEY, company_id TEXT NOT NULL, member_id INTEGER, member_email TEXT, member_role TEXT,
          expires_at TEXT NOT NULL, created_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_subscriptions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL, plan TEXT NOT NULL,
          status TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'internal',
          provider_customer_id TEXT, provider_subscription_id TEXT,
          current_period_end TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_members(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL, email TEXT NOT NULL,
          password_hash TEXT, role TEXT NOT NULL DEFAULT 'owner', status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          UNIQUE(company_id,email),
          CHECK (role IN ('owner','admin','operator','viewer')))""")
    if pg:
        conn.execute("ALTER TABLE company_sessions ADD COLUMN IF NOT EXISTS member_id BIGINT")
        conn.execute("ALTER TABLE company_sessions ADD COLUMN IF NOT EXISTS member_email TEXT")
        conn.execute("ALTER TABLE company_sessions ADD COLUMN IF NOT EXISTS member_role TEXT")
        conn.execute("ALTER TABLE company_members ADD COLUMN IF NOT EXISTS password_hash TEXT")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_invitations(
          id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL, email TEXT NOT NULL,
          role TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, inviter_email TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending', expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), accepted_at TIMESTAMPTZ)""")
        conn.execute("UPDATE company_members SET password_hash=(SELECT password_hash FROM companies c WHERE c.id=company_members.company_id) WHERE role='owner' AND password_hash IS NULL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_company_invites_company ON company_invitations(company_id,status)")
    else:
        cols={r["name"] for r in conn.execute("PRAGMA table_info(company_sessions)").fetchall()}
        for col in ("member_id","member_email","member_role"):
            if col not in cols: conn.execute("ALTER TABLE company_sessions ADD COLUMN "+col+(" INTEGER" if col=="member_id" else " TEXT"))
        mcols={r["name"] for r in conn.execute("PRAGMA table_info(company_members)").fetchall()}
        if "password_hash" not in mcols: conn.execute("ALTER TABLE company_members ADD COLUMN password_hash TEXT")
        conn.execute("""CREATE TABLE IF NOT EXISTS company_invitations(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL, email TEXT NOT NULL,
          role TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, inviter_email TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending', expires_at TEXT NOT NULL,
          created_at TEXT NOT NULL, accepted_at TEXT)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_company_invites_company ON company_invitations(company_id,status)")
        conn.execute("UPDATE company_members SET password_hash=(SELECT password_hash FROM companies c WHERE c.id=company_members.company_id) WHERE role='owner' AND password_hash IS NULL")
    if pg:
        conn.execute("""CREATE TABLE IF NOT EXISTS company_kb(
          id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL, title TEXT NOT NULL,
          content TEXT NOT NULL, source TEXT, status TEXT NOT NULL DEFAULT 'active',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_company_kb_company ON company_kb(company_id,status)")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS company_kb(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL, title TEXT NOT NULL,
          content TEXT NOT NULL, source TEXT, status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_company_kb_company ON company_kb(company_id,status)")

    if pg:
        conn.execute("""CREATE TABLE IF NOT EXISTS company_channels(
          id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL, channel_type TEXT NOT NULL,
          name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', config_json TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(company_id,name))""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_company_channels_company ON company_channels(company_id,status)")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS company_channels(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL, channel_type TEXT NOT NULL,
          name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', config_json TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(company_id,name))""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_company_channels_company ON company_channels(company_id,status)")

    if own:
        conn.commit(); conn.close()

def commercial_cookie(token,max_age=COMMERCIAL_SESSION_TTL):
    secure="; Secure" if SECURE_COOKIES else ""
    return f"{COMMERCIAL_SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={int(max_age)}{secure}"

def clear_commercial_cookie():
    secure="; Secure" if SECURE_COOKIES else ""
    return f"{COMMERCIAL_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"

def commercial_token():
    return secrets.token_urlsafe(40)

def company_from_request(handler):
    raw=handler.headers.get("Cookie","")
    token=""
    for part in raw.split(";"):
        part=part.strip()
        if part.startswith(COMMERCIAL_SESSION_COOKIE+"="):
            token=part.split("=",1)[1]
            break
    if not token: return None
    conn=db(); p="%s" if is_pg(conn) else "?"
    try:
        q="""SELECT c.*, s.member_id, COALESCE(s.member_email,c.owner_email) AS member_email,
                     COALESCE(s.member_role, m.role, 'owner') AS member_role
             FROM company_sessions s
             JOIN companies c ON c.id=s.company_id
             LEFT JOIN company_members m ON m.id=s.member_id
             WHERE s.token="""+p+""" AND s.expires_at>"""+("NOW()" if is_pg(conn) else "datetime('now')")
        rs=conn.execute(q,(token,)).fetchone()
        if not rs: return None
        c=row(rs)
        if c.get("member_id") is not None and c.get("member_role") is None: return None
        if c.get("member_role")=="owner" and c.get("member_email","").lower()!=c.get("owner_email","").lower():
            # A non-owner must always resolve to an actual active member.
            m=conn.execute("SELECT id,email,role,status FROM company_members WHERE id="+p,(c["member_id"],)).fetchone()
            if not m or m["status"]!="active": return None
        return c
    finally:
        conn.close()

def make_slug(name):
    base=re.sub(r"[^a-z0-9]+","-",str(name).lower().strip()).strip("-") or "company"
    slug=base[:40]
    conn=db(); p="%s" if is_pg(conn) else "?"
    try:
        n=0; candidate=slug
        while conn.execute("SELECT 1 FROM companies WHERE slug="+p,(candidate,)).fetchone():
            n+=1; candidate=f"{slug}-{n}"
        return candidate
    finally: conn.close()

def commercial_register(name,email,password):
    name=str(name or "").strip()[:120]
    email=str(email or "").strip().lower()
    if len(name)<2: raise ValueError("Укажите название компании")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): raise ValueError("Укажите корректный email")
    validate_password(password)
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    if conn.execute("SELECT 1 FROM companies WHERE owner_email="+p,(email,)).fetchone():
        conn.close(); raise ValueError("Компания с таким email уже зарегистрирована")
    cid=secrets.token_hex(12); slug=make_slug(name)
    if pg:
        conn.execute("INSERT INTO companies(id,name,slug,owner_email,password_hash,trial_ends_at) VALUES(%s,%s,%s,%s,%s,NOW()+INTERVAL '14 days')",(cid,name,slug,email,hash_password(password)))
        conn.execute("INSERT INTO company_subscriptions(company_id,plan,status,current_period_end) VALUES(%s,%s,%s,NOW()+INTERVAL '14 days')",(cid,"free","trialing"))
    else:
        now=time.strftime("%Y-%m-%d %H:%M:%S")
        trial=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()+14*86400))
        conn.execute("INSERT INTO companies(id,name,slug,owner_email,password_hash,trial_ends_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",(cid,name,slug,email,hash_password(password),trial,now,now))
        conn.execute("INSERT INTO company_subscriptions(company_id,plan,status,current_period_end,created_at,updated_at) VALUES(?,?,?,?,?,?)",(cid,"free","trialing",trial,now,now))
    # Register the company owner as the first tenant member.
    if pg:
        conn.execute("INSERT INTO company_members(company_id,email,password_hash,role,status) VALUES(%s,%s,%s,%s,%s)",(cid,email,hash_password(password),"owner","active"))
    else:
        conn.execute("INSERT INTO company_members(company_id,email,password_hash,role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(cid,email,hash_password(password),"owner","active",now,now))
    conn.commit()
    conn.close()
    return cid

def commercial_login(email,password):
    email=str(email or "").strip().lower()
    conn=db(); p="%s" if is_pg(conn) else "?"
    m=conn.execute("""SELECT m.*,c.name,c.slug,c.plan,c.subscription_status,c.status AS company_status
                      FROM company_members m JOIN companies c ON c.id=m.company_id
                      WHERE lower(m.email)=lower("""+p+""") AND m.status='active'""",(email,)).fetchone()
    if not m or not m["password_hash"] or not verify_password(password,m["password_hash"]):
        conn.close(); raise ValueError("Неверный email или пароль")
    if m["company_status"]!="active":
        conn.close(); raise ValueError("Компания заблокирована")
    token=commercial_token()
    if is_pg(conn):
        conn.execute("""INSERT INTO company_sessions(token,company_id,member_id,member_email,member_role,expires_at)
                        VALUES(%s,%s,%s,%s,%s,NOW()+INTERVAL '30 days')""",
                     (token,m["company_id"],m["id"],m["email"],m["role"]))
    else:
        now=time.strftime("%Y-%m-%d %H:%M:%S")
        exp=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()+COMMERCIAL_SESSION_TTL))
        conn.execute("""INSERT INTO company_sessions(token,company_id,member_id,member_email,member_role,expires_at,created_at)
                        VALUES(?,?,?,?,?,?,?)""",(token,m["company_id"],m["id"],m["email"],m["role"],exp,now))
    conn.commit(); conn.close()
    return token,{"id":m["company_id"],"name":m["name"],"slug":m["slug"],"plan":m["plan"],"subscription_status":m["subscription_status"],"member_id":m["id"],"member_email":m["email"],"member_role":m["role"],"owner_email":m["email"] if m["role"]=="owner" else None}

def company_kb_items(company_id, include_disabled=False):
    conn=db(); p="%s" if is_pg(conn) else "?"
    where="company_id="+p
    vals=[str(company_id)]
    if not include_disabled:
        where+=" AND status='active'"
    rs=conn.execute("SELECT * FROM company_kb WHERE "+where+" ORDER BY id DESC",tuple(vals)).fetchall()
    conn.close(); return [row(x) for x in rs]

def create_company_kb(company_id,title,content,source=""):
    title=str(title or "").strip()[:200]; content=str(content or "").strip()[:20000]; source=str(source or "").strip()[:500]
    if len(title)<2: raise ValueError("Укажите название материала")
    if len(content)<3: raise ValueError("Добавьте содержание материала")
    conn=db(); pg=is_pg(conn)
    if pg:
        conn.execute("INSERT INTO company_kb(company_id,title,content,source,status) VALUES(%s,%s,%s,%s,'active')",(str(company_id),title,content,source or None))
    else:
        now=time.strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO company_kb(company_id,title,content,source,status,created_at,updated_at) VALUES(?,?,?,?, 'active',?,?)",(str(company_id),title,content,source or None,now,now))
    conn.commit(); conn.close(); return True

def update_company_kb(company_id,item_id,fields):
    fields={k:v for k,v in (fields or {}).items() if k in {"title","content","source","status"}}
    if "title" in fields:
        fields["title"]=str(fields["title"] or "").strip()[:200]
        if len(fields["title"])<2: raise ValueError("Укажите название материала")
    if "content" in fields:
        fields["content"]=str(fields["content"] or "").strip()[:20000]
        if len(fields["content"])<3: raise ValueError("Добавьте содержание материала")
    if "source" in fields: fields["source"]=str(fields["source"] or "").strip()[:500]
    if "status" in fields and fields["status"] not in {"active","disabled"}: raise ValueError("Недопустимый статус")
    if not fields: return False
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    item=conn.execute("SELECT id FROM company_kb WHERE id="+p+" AND company_id="+p,(int(item_id),str(company_id))).fetchone()
    if not item: conn.close(); return False
    sets=[]; vals=[]
    for k,v in fields.items(): sets.append(k+"="+p); vals.append(v)
    sets.append("updated_at="+("NOW()" if pg else "datetime('now')"))
    vals.extend([int(item_id),str(company_id)])
    conn.execute("UPDATE company_kb SET "+", ".join(sets)+" WHERE id="+p+" AND company_id="+p,vals)
    conn.commit(); conn.close(); return True

def delete_company_kb(company_id,item_id):
    conn=db(); p="%s" if is_pg(conn) else "?"
    conn.execute("DELETE FROM company_kb WHERE id="+p+" AND company_id="+p,(int(item_id),str(company_id)))
    changed=conn.total_changes
    conn.commit(); conn.close(); return bool(changed)

def tenant_local_answer(question,company_id):
    qw=words(question); best=None; score=0
    for item in company_kb_items(company_id):
        text=(item.get("title","")+" "+item.get("content","")).strip()
        pw=words(text)
        s=len(qw & pw)/max(1,len(qw))
        if s>score: best,score=item,s
    if best and score>=.35:
        return best.get("content",""),best.get("title","База знаний"),False,best.get("source")
    return None,"unknown",False,None

def tenant_kb_context(company_id):
    return company_kb_items(company_id)

def company_channels(company_id):
    conn=db(); p="%s" if is_pg(conn) else "?"
    rs=conn.execute("SELECT id,company_id,channel_type,name,status,created_at,updated_at FROM company_channels WHERE company_id="+p+" ORDER BY id",(str(company_id),)).fetchall()
    conn.close(); return [row(x) for x in rs]

def add_company_channel(company_id,channel_type,name,status="active"):
    channel_type=str(channel_type or "").strip().lower()
    name=str(name or "").strip()[:120]
    status=str(status or "active").strip().lower()
    if channel_type not in {"web","telegram","email"}: raise ValueError("Недопустимый канал")
    if status not in {"active","disabled"}: raise ValueError("Недопустимый статус")
    if not name: raise ValueError("Укажите название канала")
    usage=company_usage(company_id)
    active=sum(1 for x in company_channels(company_id) if x.get("status")=="active")
    if usage and active >= usage["channels"]["limit"]: raise ValueError("Лимит каналов текущего тарифа исчерпан")
    conn=db(); pg=is_pg(conn)
    try:
        if pg: conn.execute("INSERT INTO company_channels(company_id,channel_type,name,status) VALUES(%s,%s,%s,%s)",(str(company_id),channel_type,name,status))
        else:
            now=time.strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("INSERT INTO company_channels(company_id,channel_type,name,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",(str(company_id),channel_type,name,status,now,now))
        conn.commit()
    except Exception as exc:
        conn.close(); raise ValueError("Канал с таким названием уже существует") from exc
    conn.close(); return True

def update_company_channel(company_id,channel_id,fields):
    fields={k:v for k,v in (fields or {}).items() if k in {"name","status"}}
    if "name" in fields:
        fields["name"]=str(fields["name"] or "").strip()[:120]
        if not fields["name"]: raise ValueError("Укажите название канала")
    if "status" in fields and fields["status"] not in {"active","disabled"}: raise ValueError("Недопустимый статус")
    if not fields: return False
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    item=conn.execute("SELECT id,status FROM company_channels WHERE id="+p+" AND company_id="+p,(int(channel_id),str(company_id))).fetchone()
    if not item: conn.close(); return False
    if fields.get("status")=="active" and item["status"]!="active":
        usage=company_usage(company_id)
        active=sum(1 for x in company_channels(company_id) if x.get("status")=="active")
        if usage and active >= usage["channels"]["limit"]: conn.close(); raise ValueError("Лимит каналов текущего тарифа исчерпан")
    sets=[]; vals=[]
    for k,v in fields.items(): sets.append(k+"="+p); vals.append(v)
    sets.append("updated_at="+("NOW()" if pg else "datetime('now')"))
    vals.extend([int(channel_id),str(company_id)])
    conn.execute("UPDATE company_channels SET "+", ".join(sets)+" WHERE id="+p+" AND company_id="+p,vals)
    conn.commit(); conn.close(); return True

def delete_company_channel(company_id,channel_id):
    conn=db(); p="%s" if is_pg(conn) else "?"
    conn.execute("DELETE FROM company_channels WHERE id="+p+" AND company_id="+p,(int(channel_id),str(company_id)))
    changed=conn.total_changes
    conn.commit(); conn.close(); return bool(changed)

def company_usage(company_id):
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    c=conn.execute("SELECT plan FROM companies WHERE id="+p,(str(company_id),)).fetchone()
    if not c:
        conn.close(); return None
    plan=str(c["plan"] or "free")
    limits=PLANS.get(plan,PLANS["free"])
    messages=int(conn.execute("SELECT COUNT(*) AS n FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE company_id="+p+")",(str(company_id),)).fetchone()["n"])
    operators=int(conn.execute("SELECT COUNT(*) AS n FROM company_members WHERE company_id="+p+" AND status='active'",(str(company_id),)).fetchone()["n"])
    tickets=int(conn.execute("SELECT COUNT(*) AS n FROM tickets WHERE company_id="+p,(str(company_id),)).fetchone()["n"])
    leads=int(conn.execute("SELECT COUNT(*) AS n FROM leads WHERE company_id="+p,(str(company_id),)).fetchone()["n"]) if _table_exists(conn,"leads") else 0
    channels_used=int(conn.execute("SELECT COUNT(*) AS n FROM company_channels WHERE company_id="+p+" AND status='active'",(str(company_id),)).fetchone()["n"]) if _table_exists(conn,"company_channels") else 0
    conn.close()
    return {"plan":plan,"messages":{"used":messages,"limit":limits["messages"]},"operators":{"used":operators,"limit":limits["operators"]},"channels":{"used":channels_used,"limit":limits["channels"]},"tickets":tickets,"leads":leads}

def _table_exists(conn,name):
    try:
        if is_pg(conn):
            return bool(conn.execute("SELECT to_regclass(%s) AS t",(name,)).fetchone()["t"])
        return bool(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone())
    except Exception:
        return False

def company_member_role(company_id,email):
    conn=db(); p="%s" if is_pg(conn) else "?"
    try:
        m=conn.execute("SELECT role FROM company_members WHERE company_id="+p+" AND lower(email)=lower("+p+") AND status='active'",(str(company_id),str(email or ""))).fetchone()
        return str(m["role"]) if m else None
    finally:
        conn.close()

def company_permission(company_id,email,permission="read"):
    role=company_member_role(company_id,email)
    if role=="owner":
        return True
    return permission in ROLE_PERMISSIONS.get(role,set())

def require_company_permission(handler,company,permission="read"):
    if not company:
        handler.send_json({"error":"authentication required"},401)
        return False
    if not company_permission(company["id"],company.get("member_email") or company.get("owner_email"),permission):
        handler.send_json({"error":"forbidden"},403)
        return False
    return True

def list_company_members(company_id):
    conn=db(); p="%s" if is_pg(conn) else "?"
    rs=conn.execute("SELECT id,email,role,status,created_at,updated_at FROM company_members WHERE company_id="+p+" ORDER BY id",(str(company_id),)).fetchall()
    conn.close(); return [row(x) for x in rs]

def add_company_member(company_id,email,role="operator"):
    email=str(email or "").strip().lower()
    if not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+",email): raise ValueError("Укажите корректный email")
    if role not in {"admin","operator","viewer"}: raise ValueError("Недопустимая роль")
    usage=company_usage(company_id)
    if usage and usage["operators"]["used"] >= usage["operators"]["limit"]: raise ValueError("Лимит операторов текущего тарифа исчерпан")
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    try:
        if pg: conn.execute("INSERT INTO company_members(company_id,email,role,status) VALUES(%s,%s,%s,'active')",(str(company_id),email,role))
        else: conn.execute("INSERT INTO company_members(company_id,email,role,status,created_at,updated_at) VALUES(?,?,?,'active',datetime('now'),datetime('now'))",(str(company_id),email,role))
        conn.commit()
    except Exception as exc:
        conn.close(); raise ValueError("Пользователь уже добавлен в компанию") from exc
    conn.close(); return True

def update_company_member(company_id,member_id,fields):
    allowed={"role","status"}; fields={k:v for k,v in (fields or {}).items() if k in allowed}
    if "role" in fields and fields["role"] not in {"owner","admin","operator","viewer"}: raise ValueError("Недопустимая роль")
    if "status" in fields and fields["status"] not in {"active","disabled"}: raise ValueError("Недопустимый статус")
    if not fields: return False
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    member=conn.execute("SELECT email,role FROM company_members WHERE id="+p+" AND company_id="+p,(int(member_id),str(company_id))).fetchone()
    if not member: conn.close(); return False
    if member["role"]=="owner" and fields.get("role")!="owner": conn.close(); raise ValueError("Владельца нельзя разжаловать")
    sets=[]; vals=[]
    for k,v in fields.items(): sets.append(k+"="+p); vals.append(v)
    sets.append("updated_at="+("NOW()" if pg else "datetime('now')"))
    vals.extend([int(member_id),str(company_id)])
    conn.execute("UPDATE company_members SET "+", ".join(sets)+" WHERE id="+p+" AND company_id="+p,vals)
    conn.commit(); conn.close(); return True

def delete_company_member(company_id,member_id):
    conn=db(); p="%s" if is_pg(conn) else "?"
    member=conn.execute("SELECT role FROM company_members WHERE id="+p+" AND company_id="+p,(int(member_id),str(company_id))).fetchone()
    if not member: conn.close(); return False
    if member["role"]=="owner": conn.close(); raise ValueError("Владельца нельзя удалить")
    conn.execute("DELETE FROM company_members WHERE id="+p+" AND company_id="+p,(int(member_id),str(company_id)))
    conn.commit(); conn.close(); return True

def create_company_invitation(company, email, role="operator"):
    email=str(email or "").strip().lower()
    if not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+",email): raise ValueError("Укажите корректный email")
    if role not in {"admin","operator","viewer"}: raise ValueError("Недопустимая роль")
    usage=company_usage(company["id"])
    if usage and usage["operators"]["used"] >= usage["operators"]["limit"]: raise ValueError("Лимит участников текущего тарифа исчерпан")
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    try:
        existing=conn.execute("SELECT role,status FROM company_members WHERE company_id="+p+" AND lower(email)=lower("+p+")",(company["id"],email)).fetchone()
        if existing and existing["status"]=="active": raise ValueError("Пользователь уже является участником компании")
        token=secrets.token_urlsafe(32); token_hash=hashlib.sha256(token.encode()).hexdigest()
        if pg:
            conn.execute("UPDATE company_invitations SET status='revoked' WHERE company_id=%s AND lower(email)=lower(%s) AND status='pending'",(company["id"],email))
            conn.execute("""INSERT INTO company_invitations(company_id,email,role,token_hash,inviter_email,expires_at)
                            VALUES(%s,%s,%s,%s,%s,NOW()+INTERVAL '7 days')""",(company["id"],email,role,token_hash,company.get("member_email") or company["owner_email"]))
        else:
            now=time.strftime("%Y-%m-%d %H:%M:%S"); exp=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()+7*86400))
            conn.execute("UPDATE company_invitations SET status='revoked' WHERE company_id=? AND lower(email)=lower(?) AND status='pending'",(company["id"],email))
            conn.execute("""INSERT INTO company_invitations(company_id,email,role,token_hash,inviter_email,expires_at,created_at)
                            VALUES(?,?,?,?,?,?,?)""",(company["id"],email,role,token_hash,company.get("member_email") or company["owner_email"],exp,now))
        conn.commit()
        return token
    finally:
        conn.close()

def list_company_invitations(company_id):
    conn=db(); p="%s" if is_pg(conn) else "?"
    rs=conn.execute("SELECT id,email,role,status,inviter_email,expires_at,created_at,accepted_at FROM company_invitations WHERE company_id="+p+" ORDER BY id DESC",(str(company_id),)).fetchall()
    conn.close(); return [row(x) for x in rs]

def accept_company_invitation(token,password):
    token=str(token or "").strip()
    if not token: raise ValueError("Недействительная ссылка приглашения")
    validate_password(password)
    token_hash=hashlib.sha256(token.encode()).hexdigest()
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    try:
        inv=conn.execute("""SELECT * FROM company_invitations
                            WHERE token_hash="""+p+""" AND status='pending' AND expires_at>"""+("NOW()" if pg else "datetime('now')"),(token_hash,)).fetchone()
        if not inv: raise ValueError("Приглашение недействительно или истекло")
        existing=conn.execute("SELECT id,role,status FROM company_members WHERE company_id="+p+" AND lower(email)=lower("+p+")",(inv["company_id"],inv["email"])).fetchone()
        now=time.strftime("%Y-%m-%d %H:%M:%S")
        if existing:
            if existing["role"]=="owner": raise ValueError("Этот email уже является владельцем")
            if pg:
                conn.execute("UPDATE company_members SET password_hash=%s,role=%s,status='active',updated_at=NOW() WHERE id=%s",(hash_password(password),inv["role"],existing["id"]))
            else:
                conn.execute("UPDATE company_members SET password_hash=?,role=?,status='active',updated_at=datetime('now') WHERE id=?",(hash_password(password),inv["role"],existing["id"]))
            member_id=existing["id"]
        else:
            if pg:
                cur=conn.execute("""INSERT INTO company_members(company_id,email,password_hash,role,status)
                                    VALUES(%s,%s,%s,%s,'active') RETURNING id""",(inv["company_id"],inv["email"],hash_password(password),inv["role"]))
                member_id=cur.fetchone()["id"]
            else:
                cur=conn.execute("""INSERT INTO company_members(company_id,email,password_hash,role,status,created_at,updated_at)
                                    VALUES(?,?,?,?, 'active',?,?)""",(inv["company_id"],inv["email"],hash_password(password),inv["role"],now,now))
                member_id=cur.lastrowid
        if pg:
            conn.execute("UPDATE company_invitations SET status='accepted',accepted_at=NOW() WHERE id=%s",(inv["id"],))
        else:
            conn.execute("UPDATE company_invitations SET status='accepted',accepted_at=datetime('now') WHERE id=?",(inv["id"],))
        token2=commercial_token()
        if pg:
            conn.execute("""INSERT INTO company_sessions(token,company_id,member_id,member_email,member_role,expires_at)
                            VALUES(%s,%s,%s,%s,%s,NOW()+INTERVAL '30 days')""",(token2,inv["company_id"],member_id,inv["email"],inv["role"]))
        else:
            exp=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()+COMMERCIAL_SESSION_TTL))
            conn.execute("""INSERT INTO company_sessions(token,company_id,member_id,member_email,member_role,expires_at,created_at)
                            VALUES(?,?,?,?,?,?,?)""",(token2,inv["company_id"],member_id,inv["email"],inv["role"],exp,now))
        conn.commit()
        c=conn.execute("SELECT * FROM companies WHERE id="+p,(inv["company_id"],)).fetchone()
        return token2,row(c)
    finally:
        conn.close()

def commercial_subscribe(company_id,plan):
    if plan not in PLANS or plan=="free": raise ValueError("Недоступный тариф")
    env_key="STRIPE_CHECKOUT_"+plan.upper()+"_URL"
    checkout=os.getenv(env_key,"").strip()
    conn=db(); p="%s" if is_pg(conn) else "?"
    now_expr="NOW()" if is_pg(conn) else "datetime('now')"
    conn.execute("UPDATE companies SET plan="+p+", subscription_status='pending', updated_at="+now_expr+" WHERE id="+p,(plan,company_id))
    if is_pg(conn):
        conn.execute("INSERT INTO company_subscriptions(company_id,plan,status,provider) VALUES(%s,%s,%s,%s)",(company_id,plan,"pending","stripe" if checkout else "internal"))
    else:
        now=time.strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO company_subscriptions(company_id,plan,status,provider,created_at,updated_at) VALUES(?,?,?,?,?,?)",(company_id,plan,"pending","stripe" if checkout else "internal",now,now))
    conn.commit(); conn.close()
    return checkout

def stripe_signature_valid(payload, signature, secret):
    if not signature or not secret: return False
    try:
        parts={}
        for item in signature.split(","):
            if "=" in item:
                k,v=item.split("=",1); parts.setdefault(k,[]).append(v)
        timestamp=int(parts.get("t",["0"])[0])
        if abs(time.time()-timestamp)>300: return False
        signed=str(timestamp).encode()+b"." + payload
        expected=hmac.new(secret.encode(),signed,hashlib.sha256).hexdigest()
        return any(secrets.compare_digest(expected,v) for v in parts.get("v1",[]))
    except Exception:
        return False

def stripe_apply_event(event):
    typ=str(event.get("type",""))
    obj=(event.get("data") or {}).get("object") or {}
    metadata=obj.get("metadata") or {}
    company_id=str(metadata.get("company_id") or "").strip()
    plan=str(metadata.get("plan") or "").strip().lower()
    if not company_id and obj.get("customer"):
        conn=db(); p="%s" if is_pg(conn) else "?"
        q="SELECT company_id,plan FROM company_subscriptions WHERE provider_customer_id="+p+" ORDER BY id DESC LIMIT 1"
        found=conn.execute(q,(str(obj.get("customer")),)).fetchone(); conn.close()
        if found: company_id=str(found["company_id"]); plan=plan or str(found["plan"])
    if not company_id: return False
    if typ=="checkout.session.completed":
        sub_id=obj.get("subscription"); customer_id=obj.get("customer")
        if not plan and obj.get("line_items") is None: plan=metadata.get("plan","")
        if plan not in PLANS or plan=="free": return False
        conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
        if pg:
            conn.execute("UPDATE companies SET plan=%s,subscription_status='active',updated_at=NOW() WHERE id=%s",(plan,company_id))
            conn.execute("UPDATE company_subscriptions SET status='active',provider='stripe',provider_customer_id=%s,provider_subscription_id=%s,updated_at=NOW() WHERE company_id=%s AND plan=%s AND status='pending'",(customer_id,sub_id,company_id,plan))
        else:
            conn.execute("UPDATE companies SET plan=?,subscription_status='active',updated_at=datetime('now') WHERE id=?",(plan,company_id))
            conn.execute("UPDATE company_subscriptions SET status='active',provider='stripe',provider_customer_id=?,provider_subscription_id=?,updated_at=datetime('now') WHERE company_id=? AND plan=? AND status='pending'",(customer_id,sub_id,company_id,plan))
        conn.commit(); conn.close(); return True
    if typ in {"customer.subscription.updated","customer.subscription.deleted"}:
        sub_id=str(obj.get("id") or "").strip(); status=str(obj.get("status") or ("canceled" if typ.endswith("deleted") else "")).lower()
        active=status in {"active","trialing"}
        if not plan:
            plan=metadata.get("plan","")
        conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
        existing=conn.execute("SELECT plan FROM company_subscriptions WHERE provider_subscription_id="+p+" ORDER BY id DESC LIMIT 1",(sub_id,)).fetchone()
        if existing and not plan: plan=str(existing["plan"])
        if plan not in PLANS or plan=="free": plan="starter" if existing and str(existing["plan"])=="starter" else plan
        if not plan: conn.close(); return False
        new_status="active" if active else ("canceled" if status in {"canceled","unpaid","incomplete_expired"} else status or "pending")
        if pg:
            conn.execute("UPDATE company_subscriptions SET status=%s,updated_at=NOW() WHERE provider_subscription_id=%s",(new_status,sub_id))
            conn.execute("UPDATE companies SET subscription_status=%s,updated_at=NOW() WHERE id=%s",(new_status,company_id))
        else:
            conn.execute("UPDATE company_subscriptions SET status=?,updated_at=datetime('now') WHERE provider_subscription_id=?",(new_status,sub_id))
            conn.execute("UPDATE companies SET subscription_status=?,updated_at=datetime('now') WHERE id=?",(new_status,company_id))
        conn.commit(); conn.close(); return True
    return False

def handle_stripe_webhook(handler):
    secret=os.getenv("STRIPE_WEBHOOK_SECRET","").strip()
    if not secret: return handler.send_json({"error":"Stripe webhook is not configured"},503)
    try:
        length=int(handler.headers.get("Content-Length","0"))
        if length>1024*1024: return handler.send_json({"error":"payload too large"},413)
        payload=handler.rfile.read(length)
        if not stripe_signature_valid(payload,handler.headers.get("Stripe-Signature",""),secret):
            return handler.send_json({"error":"invalid signature"},400)
        event=json.loads(payload.decode("utf-8"))
        stripe_apply_event(event)
        return handler.send_json({"received":True})
    except Exception as exc:
        return handler.send_json({"error":"invalid webhook payload"},400)

def commercial_get(handler,path):
    if path=="/invite":
        p=parse_qs(urlparse(handler.path).query).get("token",[""])[0]
        return handler.serve_static("invite.html") if not p else handler.serve_static("invite.html")
    if path in ("/pricing","/register","/client","/account","/login-client"):
        files={"/pricing":"pricing.html","/register":"register.html","/client":"account.html","/account":"account.html","/login-client":"register.html"}
        fname=files.get(path,"pricing.html")
        b=(BASE/"web"/fname).read_bytes()
        handler.send_response(200); handler.send_header("Content-Type","text/html; charset=utf-8"); handler.send_header("Content-Length",str(len(b))); handler.send_header("Cache-Control","no-store"); handler.end_headers(); handler.wfile.write(b); return True
    if path=="/api/commercial/me":
        c=company_from_request(handler)
        if not c: return handler.send_json({"authenticated":False},200) or True
        return handler.send_json({"authenticated":True,"company":{"id":c["id"],"name":c["name"],"slug":c["slug"],"email":c.get("member_email") or c["owner_email"],"owner_email":c["owner_email"],"member_id":c.get("member_id"),"member_role":c.get("member_role","owner"),"plan":c["plan"],"subscription_status":c["subscription_status"],"trial_ends_at":c["trial_ends_at"],"status":c["status"]}})
    if path=="/api/commercial/usage":
        c=company_from_request(handler)
        if not c: return handler.send_json({"error":"authentication required"},401) or True
        return handler.send_json({"usage":company_usage(c["id"])})
    if path=="/api/commercial/invitations/preview":
        token=parse_qs(urlparse(handler.path).query).get("token",[""])[0]
        token_hash=hashlib.sha256(str(token).encode()).hexdigest()
        conn=db(); p="%s" if is_pg(conn) else "?"
        try:
            inv=conn.execute("""SELECT email,role,expires_at FROM company_invitations
                                WHERE token_hash="""+p+""" AND status='pending' AND expires_at>"""+("NOW()" if is_pg(conn) else "datetime('now')"),(token_hash,)).fetchone()
            if not inv: return handler.send_json({"error":"Приглашение недействительно или истекло"},404)
            return handler.send_json({"email":inv["email"],"role":inv["role"],"expires_at":inv["expires_at"]})
        finally:
            conn.close()

    if path=="/api/commercial/invitations":
        c=company_from_request(handler)
        if not c: return handler.send_json({"error":"authentication required"},401)
        if not require_company_permission(handler,c,"manage"): return
        return handler.send_json({"invitations":list_company_invitations(c["id"])})

    if path=="/api/commercial/channels":
        c=company_from_request(handler)
        if not require_company_permission(handler,c,"read"): return
        items=company_channels(c["id"])
        return handler.send_json({"channels":items,"limit":PLANS.get(c.get("plan"),PLANS["free"])["channels"]})

    if path=="/api/commercial/members":
        c=company_from_request(handler)
        if not require_company_permission(handler,c,"read"): return
        return handler.send_json({"members":list_company_members(c["id"])})
    return False

def commercial_post(handler,path):
    if path=="/api/commercial/channels":
        c=company_from_request(handler)
        if not require_company_permission(handler,c,"manage"): return
        try:
            p=handler.body()
            add_company_channel(c["id"],p.get("channel_type","web"),p.get("name"),p.get("status","active"))
            return handler.send_json({"ok":True,"channels":company_channels(c["id"])},201)
        except ValueError as e:
            return handler.send_json({"error":str(e)},400)
    if path=="/api/kb":
        c=company_from_request(handler)
        if not require_company_permission(handler,c,"manage"): return
        try:
            p=handler.body()
            create_company_kb(c["id"],p.get("title"),p.get("content"),p.get("source",""))
            return handler.send_json({"ok":True,"items":company_kb_items(c["id"])},201)
        except ValueError as e:
            return handler.send_json({"error":str(e)},400)
    if path=="/api/commercial/invitations":
        c=company_from_request(handler)
        if not require_company_permission(handler,c,"manage"): return
        try:
            p=handler.body(); token=create_company_invitation(c,p.get("email"),p.get("role","operator"))
            host=handler.headers.get("Host","")
            scheme="https" if (SECURE_COOKIES or handler.headers.get("X-Forwarded-Proto")=="https" or host.endswith(".up.railway.app")) else "http"
            return handler.send_json({"ok":True,"email":str(p.get("email","")).strip().lower(),"role":p.get("role","operator"),"invite_url":scheme+"://"+host+"/invite?token="+token},201)
        except ValueError as e: return handler.send_json({"error":str(e)},400)
    if path=="/api/commercial/invitations/accept":
        try:
            p=handler.body(); token,c=accept_company_invitation(p.get("token"),p.get("password"))
            handler._set_commercial_cookie=token
            return handler.send_json({"ok":True,"company":{"id":c["id"],"name":c["name"],"plan":c["plan"],"subscription_status":c["subscription_status"],"member_id":c.get("member_id"),"member_email":c.get("member_email"),"member_role":c.get("member_role","owner")}})
        except ValueError as e: return handler.send_json({"ok":False,"error":str(e)},400)
    if path=="/api/commercial/register":
        try:
            p=handler.body(); cid=commercial_register(p.get("company"),p.get("email"),p.get("password"))
            token,c=commercial_login(p.get("email"),p.get("password"))
            handler._set_commercial_cookie=token
            return handler.send_json({"ok":True,"company":{"id":c["id"],"name":c["name"],"slug":c["slug"],"plan":"free","subscription_status":"trialing"}})
        except ValueError as e: return handler.send_json({"ok":False,"error":str(e)},400)
    if path=="/api/commercial/login":
        try:
            p=handler.body(); token,c=commercial_login(p.get("email"),p.get("password"))
            handler._set_commercial_cookie=token
            return handler.send_json({"ok":True,"company":{"id":c["id"],"name":c["name"],"slug":c["slug"],"plan":c["plan"],"subscription_status":c["subscription_status"]}})
        except ValueError as e: return handler.send_json({"ok":False,"error":str(e)},401)
    if path=="/api/commercial/logout":
        handler._clear_commercial_cookie=True
        return handler.send_json({"ok":True})
    if path=="/api/commercial/subscribe":
        c=company_from_request(handler)
        if not c: return handler.send_json({"error":"authentication required"},401)
        try:
            p=handler.body(); plan=str(p.get("plan","")).lower(); checkout=commercial_subscribe(c["id"],plan)
            return handler.send_json({"ok":True,"plan":plan,"checkout_url":checkout or None,"message":"Откройте оплату Stripe, когда она подключена."})
        except ValueError as e: return handler.send_json({"error":str(e)},400)
    if path=="/api/commercial/members":
        c=company_from_request(handler)
        if not c: return handler.send_json({"error":"authentication required"},401)
        try:
            p=handler.body(); add_company_member(c["id"],p.get("email"),p.get("role","operator"))
            return handler.send_json({"ok":True,"members":list_company_members(c["id"])},201)
        except ValueError as e: return handler.send_json({"error":str(e)},400)
    return False

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
        if getattr(self,"_clear_commercial_cookie",False):
            self.send_header("Set-Cookie",clear_commercial_cookie())
        elif getattr(self,"_set_commercial_cookie",""):
            self.send_header("Set-Cookie",commercial_cookie(self._set_commercial_cookie))
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
        if commercial_get(self,path): return
        if path=="/api/health":
            conn=None
            try:
                conn=db()
                operator_count=int(conn.execute("SELECT COUNT(*) AS n FROM operators").fetchone()["n"])
            except Exception:
                operator_count=0
            finally:
                if conn is not None:
                    conn.close()
            configured=bool(ADMIN_PASSWORD or OPERATORS_JSON)
            return self.send_json({"ok":True,"service":"SupportPilot","version":"2.0","database":"postgres" if DATABASE_URL else "sqlite-fallback","ai":bool(AI_API_KEY),"auth":configured or operator_count>0,"setup_required":not configured and operator_count==0})
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
            company=company_from_request(self)
            if company:
                return self.send_json({"items":company_kb_items(company["id"]),"count":len(company_kb_items(company["id"]))})
            return self.send_json({"items":KB,"count":len(KB)})
        if path.startswith("/api/conversations/") and path.endswith("/messages"):
            company=company_from_request(self)
            if not company and not self.require(): return
            conversation_id=path.split("/")[3]
            messages=list_messages(conversation_id,company_id=company["id"] if company else None)
            if company and not messages:
                conn=db(); p="%s" if is_pg(conn) else "?"
                exists=conn.execute("SELECT id FROM conversations WHERE id="+p+" AND company_id="+p,(conversation_id,company["id"])).fetchone()
                conn.close()
                if not exists: return self.send_json({"error":"conversation not found"},404)
            return self.send_json({"conversation_id":conversation_id,"messages":messages})
        if path=="/api/leads":
            company=company_from_request(self)
            if not company and not self.require(): return
            from lead_pipeline import list_leads
            params=parse_qs(urlparse(self.path).query)
            status=params.get("status",[None])[0]
            search=params.get("q",[""])[0]
            if status:
                from lead_pipeline import LEAD_STATUSES
                if status not in LEAD_STATUSES:
                    return self.send_json({"error":"invalid lead status"},400)
            company=company_from_request(self)
            return self.send_json({"leads":list_leads(status=status,search=search,company_id=company["id"] if company else None)})
        if path.startswith("/api/commercial/channels/"):
            c=company_from_request(self)
            if not require_company_permission(self,c,"manage"): return
            try:
                cid=int(path.rsplit("/",1)[1])
                ok=update_company_channel(c["id"],cid,self.body())
                return self.send_json({"ok":bool(ok),"channels":company_channels(c["id"])},200 if ok else 404)
            except (ValueError,TypeError) as e:
                return self.send_json({"error":str(e)},400)
        if path.startswith("/api/kb/"):
            c=company_from_request(self)
            if not require_company_permission(self,c,"manage"): return
            try:
                item_id=int(path.rsplit("/",1)[1])
                ok=update_company_kb(c["id"],item_id,self.body())
                return self.send_json({"ok":bool(ok),"items":company_kb_items(c["id"])},200 if ok else 404)
            except (ValueError,TypeError) as e:
                return self.send_json({"error":str(e)},400)
        if path.startswith("/api/commercial/members/"):
            c=company_from_request(self)
            if not require_company_permission(self,c,"manage"): return
            try:
                ok=update_company_member(c["id"],int(path.rsplit("/",1)[1]),self.body())
            except (ValueError,TypeError) as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":bool(ok)},200 if ok else 404)

        if path.startswith("/api/leads/"):
            company=company_from_request(self)
            if company and not require_company_permission(self,company,"write"): return
            if not company and not self.require("write"): return
            from lead_pipeline import get_lead, list_lead_events
            lead_id=path.rsplit("/",1)[1]
            company=company_from_request(self)
            lead=get_lead(lead_id,company_id=company["id"] if company else None)
            return self.send_json({"lead":lead,"events":list_lead_events(lead_id,company_id=company["id"] if company else None)} if lead else {"error":"lead not found"},200 if lead else 404)
        if path=="/api/tickets":
            company=company_from_request(self)
            if company:
                params=parse_qs(urlparse(self.path).query)
                try: tickets=list_tickets(status=params.get("status",[None])[0],priority=params.get("priority",[None])[0],search=params.get("q",[""])[0],company_id=company["id"])
                except ValueError as e: return self.send_json({"error":str(e)},400)
                return self.send_json({"tickets":tickets})
            if not self.require(): return
            params=parse_qs(urlparse(self.path).query)
            status=params.get("status",[None])[0]; priority=params.get("priority",[None])[0]
            search=params.get("q",[""])[0]; assignee=params.get("assignee",[""])[0]
            unassigned=params.get("unassigned",["0"])[0] in ("1","true","yes")
            if assignee=="__unassigned__": assignee=""; unassigned=True
            try: tickets=list_tickets(status=status,priority=priority,search=search,assignee=assignee,unassigned=unassigned)
            except ValueError as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"tickets":tickets})
        if path.startswith("/api/tickets/"):
            company=company_from_request(self)
            if not company and not self.require(): return
            try: tid=int(path.rsplit("/",1)[1])
            except ValueError: return self.send_json({"error":"invalid ticket id"},400)
            ticket=get_ticket(tid,company_id=company["id"] if company else None)
            if not ticket: return self.send_json({"error":"ticket not found"},404)
            return self.send_json({"ticket":ticket,"events":list_ticket_events(tid,company_id=company["id"] if company else None)})
            if not self.require(): return
            try: tid=int(path.rsplit("/",1)[1])
            except ValueError: return self.send_json({"error":"invalid ticket id"},400)
            ticket=get_ticket(tid)
            if not ticket: return self.send_json({"error":"ticket not found"},404)
            return self.send_json({"ticket":ticket,"events":list_ticket_events(tid)})
        if path=="/api/customers/detail":
            company=company_from_request(self)
            if not require_company_permission(self,company,"read"): return
            params=parse_qs(urlparse(self.path).query)
            identifier=params.get("email",[""])[0] or params.get("name",[""])[0]
            detail=get_customer_detail(identifier,company_id=company["id"])
            return self.send_json({"customer":detail} if detail else {"error":"customer not found"},200 if detail else 404)
        if path=="/api/customers":
            company=company_from_request(self)
            if not company and not self.require(): return
            search=parse_qs(urlparse(self.path).query).get("q",[""])[0]
            return self.send_json({"customers":list_customers(search=search,company_id=company["id"] if company else None)})
        if path=="/api/stats":
            company=company_from_request(self)
            if company:
                return self.send_json(stats(company_id=company["id"]))
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
        if path != "/api/webhooks/stripe" and path not in ("/api/login","/api/setup-admin","/api/chat","/api/leads","/api/commercial/register","/api/commercial/login","/api/commercial/logout","/api/commercial/subscribe","/api/commercial/invitations","/api/commercial/invitations/accept") and not self._require_csrf():
            return
        if commercial_post(self,path): return
        try: p=self.body()
        except ValueError as e: return self.send_json({"error":str(e)},413 if "large" in str(e) else 400)
        if path=="/api/setup-admin":
            email=str(p.get("email","")).strip().lower()
            password=str(p.get("password",""))
            if ADMIN_PASSWORD or OPERATORS_JSON:
                return self.send_json({"error":"Admin setup is already configured"},409)
            conn=db()
            try:
                count=int(conn.execute("SELECT COUNT(*) AS n FROM operators").fetchone()["n"])
                if count:
                    return self.send_json({"error":"Admin setup has already been completed"},409)
                if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email):
                    return self.send_json({"error":"invalid operator email"},400)
                validate_password(password)
                encoded=hash_password(password)
                if is_pg(conn):
                    conn.execute("INSERT INTO operators(email,password_hash,role) VALUES(%s,%s,%s)",(email,encoded,"admin"))
                else:
                    conn.execute("INSERT INTO operators(email,password_hash,role,created_at) VALUES(?,?,?,datetime('now'))",(email,encoded,"admin"))
                conn.commit()
            except ValueError as e:
                return self.send_json({"error":str(e)},400)
            finally:
                conn.close()
            self._set_session_cookie=make_token(email,"admin")
            return self.send_json({"ok":True,"user":{"email":email,"role":"admin"}})
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
            # First-run bootstrap also works through the normal login endpoint.
            # This keeps older cached frontends usable while the setup screen rolls out.
            if not op and not ADMIN_PASSWORD and not OPERATORS_JSON:
                try:
                    count=int(conn.execute("SELECT COUNT(*) AS n FROM operators").fetchone()["n"])
                    if count==0:
                        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email):
                            conn.close()
                            return self.send_json({"ok":False,"error":"invalid operator email"},400)
                        validate_password(password)
                        encoded=hash_password(password)
                        if is_pg(conn):
                            conn.execute("INSERT INTO operators(email,password_hash,role) VALUES(%s,%s,%s)",(email.lower(),encoded,"admin"))
                        else:
                            conn.execute("INSERT INTO operators(email,password_hash,role,created_at) VALUES(?,?,?,datetime('now'))",(email.lower(),encoded,"admin"))
                        conn.commit()
                        conn.close()
                        LOGIN_RATE.pop(client,None)
                        self._set_session_cookie=make_token(email.lower(),"admin")
                        return self.send_json({"ok":True,"user":{"email":email.lower(),"role":"admin"},"setup":True})
                except ValueError as e:
                    conn.close()
                    return self.send_json({"ok":False,"error":str(e)},400)
                except Exception:
                    conn.rollback()
                    conn.close()
                    return self.send_json({"ok":False,"error":"first-run setup failed"},500)
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
        if path=="/api/tickets":
            company=company_from_request(self)
            if not company: return self.send_json({"error":"commercial authentication required"},401)
            question=redact_sensitive(str(p.get("question","")).strip())[:MAX_MESSAGE_CHARS]
            answer=redact_sensitive(str(p.get("answer","")).strip())[:MAX_MESSAGE_CHARS]
            if not question or not answer: return self.send_json({"error":"question and answer are required"},400)
            tid=create_ticket(question,answer,str(p.get("status","open")),str(p.get("reason","")),str(p.get("customer_name","")),str(p.get("customer_email","")),company_id=company["id"])
            return self.send_json({"ok":True,"ticket_id":tid},201)
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
            company=company_from_request(self)
            if company and not require_company_permission(self,company,"write"): return
            result=answer_question(p.get("message",""),p.get("name",""),p.get("email",""),p.get("conversation_id",""),company_id=company["id"] if company else None); return self.send_json(result)
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
                company=company_from_request(self)
                if company and not require_company_permission(self,company,"write"): return
                lead_id=create_lead(p,company_id=company["id"] if company else None)
            except ValueError as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":True,"leadId":lead_id,"status":"NEW"},202)
        self.send_json({"error":"not found"},404)
    def do_DELETE(self):
        if self.path.split("?",1)[0].startswith("/api/commercial/channels/"):
            c=company_from_request(self)
            if not require_company_permission(self,c,"manage"): return
            try:
                cid=int(self.path.split("?",1)[0].rsplit("/",1)[1])
                ok=delete_company_channel(c["id"],cid)
                return self.send_json({"ok":bool(ok)},200 if ok else 404)
            except (ValueError,TypeError) as e:
                return self.send_json({"error":str(e)},400)

        if path.startswith("/api/kb/"):
            c=company_from_request(self)
            if not require_company_permission(self,c,"manage"): return
            try:
                item_id=int(path.rsplit("/",1)[1])
                ok=delete_company_kb(c["id"],item_id)
                return self.send_json({"ok":bool(ok)},200 if ok else 404)
            except (ValueError,TypeError) as e:
                return self.send_json({"error":str(e)},400)

        path=urlparse(self.path).path
        if not self._require_csrf():
            return
        if path.startswith("/api/commercial/members/"):
            c=company_from_request(self)
            if not require_company_permission(self,c,"manage"): return
            try: ok=delete_company_member(c["id"],int(path.rsplit("/",1)[1]))
            except (ValueError,TypeError) as e: return self.send_json({"error":str(e)},400)
            return self.send_json({"ok":bool(ok)},200 if ok else 404)
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
            company=company_from_request(self)
            s=self.require("write") if not company else None
            if not company and not s: return
            try:
                from lead_pipeline import update_lead
                lead_id=path.rsplit("/",1)[1]
                body=self.body()
                actor=company["owner_email"] if company else s["email"]
                ok=update_lead(lead_id,body,actor=actor,company_id=company["id"] if company else None)
            except ValueError as e: return self.send_json({"error":str(e)},400)
            except Exception:
                return self.send_json({"error":"lead update failed"},500)
            if not ok:
                return self.send_json({"error":"lead not found"},404)
            return self.send_json({"ok":True})
        if path.startswith("/api/tickets/"):
            company=company_from_request(self)
            if company:
                if not require_company_permission(self,company,"write"): return
                try: tid=int(path.rsplit("/",1)[1]); ok=update_ticket(tid,self.body(),actor=company.get("member_email") or company["owner_email"],company_id=company["id"])
                except ValueError as e: return self.send_json({"error":str(e)},400)
                except Exception: return self.send_json({"error":"ticket update failed"},500)
                return self.send_json({"ok":bool(ok)})
            s=self.require("write")
            if not s: return
            try: tid=int(path.rsplit("/",1)[1]); ok=update_ticket(tid,self.body(),actor=s["email"])
            except ValueError as e: return self.send_json({"error":str(e)},400)
            except Exception: return self.send_json({"error":"ticket update failed"},500)
            return self.send_json({"ok":bool(ok)})

if __name__=="__main__":
    init_db(); ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()