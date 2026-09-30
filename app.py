    elif "status" in fields: sets.append("resolved_at=NULL")
    vals.append(tid); vals.extend(scope_vals)
    conn.execute(f"UPDATE tickets SET {', '.join(sets)} WHERE id={p}{scope}",vals)
    after={k:fields.get(k,before[k]) for k in before}; changes={k:{"from":before[k],"to":after[k]} for k in before if before[k]!=after[k]}
    if changes:
        details=json.dumps(changes,ensure_ascii=False)
        if pg: conn.execute("INSERT INTO ticket_events(ticket_id,company_id,actor,action,details) VALUES(%s,%s,%s,%s,%s)",(tid,company_id,str(actor)[:160],"ticket.updated",details))
        else: conn.execute("INSERT INTO ticket_events(ticket_id,company_id,actor,action,details,created_at) VALUES(?,?,?,?,?,datetime('now'))",(tid,company_id,str(actor)[:160],"ticket.updated",details))
        if after.get("assignee"): create_notification("assignment","Вам назначено обращение",f"Обращение #{tid}",tid,str(after["assignee"]).strip().lower(),company_id=company_id,conn=conn)
        if after.get("status") in ("escalated","open"): create_notification("ticket","Обновлено обращение",f"Обращение #{tid}: статус {after.get('status')}",tid,company_id=company_id,conn=conn)
    conn.commit(); conn.close(); return True

def add_ticket_reply(tid, message, actor="operator", company_id=None):
    message=redact_sensitive(str(message or "").strip())[:MAX_MESSAGE_CHARS]
    if not message: raise ValueError("reply message is required")
    ticket=get_ticket(tid,company_id=company_id)