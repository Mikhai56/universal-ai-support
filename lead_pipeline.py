import re, secrets, time
from app import db, is_pg, redact_sensitive

LEAD_STATUSES = ("NEW","RESEARCHING","QUALIFIED","PENDING_APPROVAL","SENT","REJECTED","FAILED")
LEAD_TRANSITIONS = {
    "NEW": {"RESEARCHING", "REJECTED"},
    "RESEARCHING": {"QUALIFIED", "REJECTED", "FAILED"},
    "QUALIFIED": {"PENDING_APPROVAL", "REJECTED"},
    "PENDING_APPROVAL": {"SENT", "REJECTED"},
    "SENT": set(),
    "REJECTED": set(),
    "FAILED": {"RESEARCHING"},
}
MAX_LEAD_BODY = 16 * 1024
CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

def init_leads(conn):
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS leads(
          id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, phone TEXT,
          company TEXT, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'NEW',
          research TEXT, qualification_category TEXT, qualification_reason TEXT,
          generated_email TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          CHECK (status IN ('NEW','RESEARCHING','QUALIFIED','PENDING_APPROVAL','SENT','REJECTED','FAILED'))
        )""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS leads(
          id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, phone TEXT,
          company TEXT, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'NEW',
          research TEXT, qualification_category TEXT, qualification_reason TEXT,
          generated_email TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          CHECK (status IN ('NEW','RESEARCHING','QUALIFIED','PENDING_APPROVAL','SENT','REJECTED','FAILED'))
        )""")
    init_lead_events(conn)

def init_lead_events(conn):
    if is_pg(conn):
        conn.execute("""CREATE TABLE IF NOT EXISTS lead_events(
          id BIGSERIAL PRIMARY KEY, lead_id TEXT NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, details TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    else:
        conn.execute("""CREATE TABLE IF NOT EXISTS lead_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, lead_id TEXT NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL)""")

def sanitize_phone(value):
    phone = str(value or "").strip()[:80]
    return CARD_PATTERN.sub("[ДАННЫЕ КАРТЫ УДАЛЕНЫ]", phone)

def create_lead(data):
    if not isinstance(data, dict): raise ValueError("JSON body must be an object")
    name=str(data.get("name","")).strip()[:200]
    email=str(data.get("email","")).strip()[:320]
    phone=sanitize_phone(data.get("phone",""))
    company=str(data.get("company","")).strip()[:200]
    message=redact_sensitive(str(data.get("message","")).strip())[:MAX_LEAD_BODY]
    research=redact_sensitive(str(data.get("research","")).strip())[:MAX_LEAD_BODY]
    qualification_reason=redact_sensitive(str(data.get("qualification_reason","")).strip())[:2000]
    generated_email=redact_sensitive(str(data.get("generated_email","")).strip())[:MAX_LEAD_BODY]
    if not name or not email or not message: raise ValueError("name, email and message are required")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): raise ValueError("invalid email")
    lead_id=secrets.token_hex(16)
    now=time.strftime("%Y-%m-%d %H:%M:%S")
    conn=db()
    if is_pg(conn):
        conn.execute("INSERT INTO leads(id,email,name,phone,company,message,research,qualification_reason,generated_email) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(lead_id,email,name,phone,company,message,research,qualification_reason,generated_email))
    else:
        conn.execute("INSERT INTO leads(id,email,name,phone,company,message,research,qualification_reason,generated_email,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(lead_id,email,name,phone,company,message,research,qualification_reason,generated_email,now,now))
    conn.commit(); conn.close()
    return lead_id

def list_leads(status=None, limit=100):
    conn=db()
    limit=min(max(int(limit),1),100)
    if is_pg(conn):
        rs=conn.execute("SELECT * FROM leads WHERE status=%s ORDER BY created_at DESC LIMIT %s",(status,limit)).fetchall() if status else conn.execute("SELECT * FROM leads ORDER BY created_at DESC LIMIT %s",(limit,)).fetchall()
    else:
        rs=conn.execute("SELECT * FROM leads WHERE status=? ORDER BY created_at DESC LIMIT ?",(status,limit)).fetchall() if status else conn.execute("SELECT * FROM leads ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall()
    conn.close(); return [dict(x) for x in rs]

def get_lead(lead_id):
    conn=db()
    if is_pg(conn):
        r=conn.execute("SELECT * FROM leads WHERE id=%s",(lead_id,)).fetchone()
    else:
        r=conn.execute("SELECT * FROM leads WHERE id=?",(lead_id,)).fetchone()
    conn.close()
    return dict(r) if r else None

def list_lead_events(lead_id, limit=100):
    limit=min(max(int(limit),1),100)
    conn=db(); pg=is_pg(conn); p="%s" if pg else "?"
    try:
        rs=conn.execute(f"SELECT * FROM lead_events WHERE lead_id={p} ORDER BY id DESC LIMIT {p}",(lead_id,limit)).fetchall()
    except Exception:
        rs=[]
    conn.close()
    return [dict(x) for x in rs]

def update_lead(lead_id, fields, actor="admin"):
    if not isinstance(fields, dict): raise ValueError("JSON body must be an object")
    allowed={"status","research","qualification_category","qualification_reason","generated_email"}
    fields={k:v for k,v in fields.items() if k in allowed}
    if "status" in fields and fields["status"] not in LEAD_STATUSES: raise ValueError("invalid lead status")
    if not fields: return False
    conn=db(); pg=is_pg(conn)
    current = conn.execute("SELECT status FROM leads WHERE id="+("%s" if pg else "?"),(lead_id,)).fetchone()
    if not current:
        conn.close()
        return False
    current_status = current["status"] if isinstance(current, dict) else current[0]
    requested_status = fields.get("status")
    if requested_status and requested_status != current_status and requested_status not in LEAD_TRANSITIONS[current_status]:
        conn.close()
        raise ValueError("invalid lead status transition")
    sets=[]; vals=[]
    for k,v in fields.items():
        if isinstance(v, str):
            limit=200 if k=="qualification_category" else 2000 if k=="qualification_reason" else MAX_LEAD_BODY
            v=redact_sensitive(v)[:limit]
        sets.append(f"{k}={'%s' if pg else '?'}"); vals.append(v)
    sets.append("updated_at=NOW()" if pg else "updated_at=datetime('now')"); vals.append(lead_id)
    conn.execute(f"UPDATE leads SET {', '.join(sets)} WHERE id={'%s' if pg else '?'}",vals)
    changed=conn.execute("SELECT 1 FROM leads WHERE id="+("%s" if pg else "?"),(lead_id,)).fetchone()
    if changed:
        import json
        details=json.dumps({"status":{"from":current_status,"to":fields.get("status",current_status)}},ensure_ascii=False)
        if pg:
            conn.execute("INSERT INTO lead_events(lead_id,actor,action,details) VALUES(%s,%s,%s,%s)",(str(lead_id),str(actor)[:160],"lead.updated",details))
        else:
            conn.execute("INSERT INTO lead_events(lead_id,actor,action,details,created_at) VALUES(?,?,?,?,datetime('now'))",(str(lead_id),str(actor)[:160],"lead.updated",details))
    conn.commit(); conn.close(); return bool(changed)
