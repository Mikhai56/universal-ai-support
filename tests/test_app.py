import json
import os
import tempfile
import unittest


def load_app():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    os.environ['DB_PATH'] = tmp.name
    import app
    app.DB_PATH = tmp.name
    app.init_db()
    return app, tmp.name


class SupportPilotTests(unittest.TestCase):
    def test_known_question(self):
        app, path = load_app()
        result = app.answer_question('Есть доставка по России?')
        self.assertEqual(result['status'], 'answered')
        self.assertIn('России', result['answer'])
        os.unlink(path)

    def test_unknown_question_creates_clarification(self):
        app, path = load_app()
        result = app.answer_question('Расскажите о совершенно неизвестной функции')
        self.assertEqual(result['status'], 'needs_clarification')
        self.assertIn('не нашёл точного ответа', result['answer'])
        os.unlink(path)

    def test_sensitive_payment_is_escalated(self):
        app, path = load_app()
        result = app.answer_question('У меня данные карты 4111 1111 1111 1111 и двойное списание')
        self.assertEqual(result['status'], 'escalated')
        self.assertTrue(result['ticket_id'])
        os.unlink(path)

    def test_ticket_detail_and_validation(self):
        app, path = load_app()
        result = app.answer_question("Как оформить возврат?")
        tid = result["ticket_id"]
        ticket = app.get_ticket(tid)
        self.assertEqual(ticket["id"], tid)
        self.assertIn("question", ticket)
        self.assertTrue(app.update_ticket(tid, {"status":"resolved","priority":"high","assignee":"Оператор"}))
        updated = app.get_ticket(tid)
        self.assertEqual(updated["status"], "resolved")
        self.assertEqual(updated["priority"], "high")
        self.assertEqual(updated["assignee"], "Оператор")
        with self.assertRaises(ValueError):
            app.update_ticket(tid, {"status":"not-a-real-status"})
        os.unlink(path)

    def test_customer_crm_aggregation_and_lead_link(self):
        app, path = load_app()
        first = app.create_ticket("Первый вопрос", "Ответ", "open", customer_name="Анна", customer_email="anna@example.com")
        app.create_ticket("Второй вопрос", "Ответ", "escalated", "платёжный инцидент", customer_name="Анна", customer_email="anna@example.com")
        from lead_pipeline import create_lead
        create_lead({"name":"Анна","email":"anna@example.com","company":"Example","message":"Нужна консультация"})
        customers = app.list_customers()
        self.assertEqual(len(customers), 1)
        customer = customers[0]
        self.assertEqual(customer["email"], "anna@example.com")
        self.assertEqual(customer["total_tickets"], 2)
        self.assertEqual(customer["open_tickets"], 2)
        self.assertEqual(customer["escalated_tickets"], 1)
        self.assertEqual({t["id"] for t in customer["tickets"]}, {first, first + 1})
        self.assertEqual(len(customer["leads"]), 1)
        self.assertEqual(customer["leads"][0]["email"], "anna@example.com")
        self.assertEqual(len(app.list_customers(search="anna@example.com")), 1)
        self.assertEqual(len(app.list_customers(search="nobody@example.com")), 0)
        os.unlink(path)

    def test_ticket_filters_and_search(self):
        app, path = load_app()
        first = app.create_ticket("Какой срок доставки?", "До 5 дней", "open", customer_name="Анна", customer_email="anna@example.com")
        second = app.create_ticket("Нужна помощь с оплатой", "Передано оператору", "escalated", "платёжный инцидент", customer_name="Иван", customer_email="ivan@example.com")
        self.assertEqual([x["id"] for x in app.list_tickets(status="open")], [first])
        self.assertEqual([x["id"] for x in app.list_tickets(priority="high")], [second])
        self.assertEqual([x["id"] for x in app.list_tickets(search="anna@example.com")], [first])
        self.assertEqual([x["id"] for x in app.list_tickets(search="доставки")], [first])
        with self.assertRaises(ValueError):
            app.list_tickets(status="invalid")
        with self.assertRaises(ValueError):
            app.list_tickets(priority="invalid")
        os.unlink(path)

    def test_operator_management_and_last_admin_protection(self):
        app, path = load_app()
        app.create_operator("admin@example.com","adminpass","admin")
        app.create_operator("viewer@example.com","viewerpass","viewer")
        app.create_operator("operator@example.com","operatorpass","operator")
        ops={x["email"]:x for x in app.list_operators()}
        self.assertEqual(ops["viewer@example.com"]["role"],"viewer")
        self.assertNotIn("password_hash",ops["viewer@example.com"])
        self.assertTrue(app.update_operator("viewer@example.com",{"role":"operator","password":"newviewerpass"}))
        conn=app.db()
        stored=conn.execute("SELECT password_hash FROM operators WHERE email=?", ("viewer@example.com",)).fetchone()["password_hash"]
        conn.close()
        self.assertTrue(app.verify_password("newviewerpass", stored))
        self.assertTrue(app.delete_operator("operator@example.com"))
        with self.assertRaises(ValueError):
            app.delete_operator("admin@example.com")
        os.environ.pop("ADMIN_PASSWORD",None)
        os.unlink(path)


    def test_auth_permissions_and_expiry(self):
        app, path = load_app()
        app.create_operator("admin@example.com", "adminpass", "admin")
        app.create_operator("operator@example.com", "operatorpass", "operator")
        app.create_operator("viewer@example.com", "viewerpass", "viewer")
        tokens = {role: app.make_token(role+"@example.com", role) for role in ("admin", "operator", "viewer")}
        for role, tok in tokens.items():
            headers = {"Authorization": "Bearer " + tok}
            self.assertIsNotNone(app.auth(headers, "read"))
            self.assertEqual(app.auth(headers, "write") is not None, role in ("admin", "operator"))
            self.assertEqual(app.auth(headers, "manage") is not None, role == "admin")
        app.SESSIONS[tokens["operator"]]["expires"] = 0
        self.assertIsNone(app.auth({"Authorization": "Bearer " + tokens["operator"]}, "read"))
        os.unlink(path)

    def test_lead_audit_records_authenticated_actor(self):
        app, path = load_app()
        from lead_pipeline import create_lead, list_lead_events, update_lead
        lead_id = create_lead({"name": "Иван", "email": "ivan@example.com", "message": "Нужна консультация"})
        self.assertTrue(update_lead(lead_id, {"status": "RESEARCHING"}, actor="operator@example.com"))
        events = list_lead_events(lead_id)
        self.assertEqual(events[0]["actor"], "operator@example.com")
        os.unlink(path)

    def test_session_cookie_security_flags(self):
        app, path = load_app()
        previous = app.SECURE_COOKIES
        try:
            app.SECURE_COOKIES = True
            cookie = app.session_cookie("abc123")
            self.assertIn("HttpOnly", cookie)
            self.assertIn("Secure", cookie)
            self.assertIn("SameSite=Lax", cookie)
            self.assertIn("Max-Age=43200", cookie)
            cleared = app.clear_session_cookie()
            self.assertIn("Max-Age=0", cleared)
            self.assertIn("Secure", cleared)
        finally:
            app.SECURE_COOKIES = previous
            os.unlink(path)

    def test_conversation_persistence_and_redaction(self):
        app, path = load_app()
        first = app.answer_question("Как оформить возврат?", name="Анна", email="anna@example.com")
        self.assertRegex(first["conversation_id"], r"^[a-f0-9]{32}$")
        second = app.answer_question("Вот данные карты 4111 1111 1111 1111", name="Анна", email="anna@example.com", conversation_id=first["conversation_id"])
        self.assertEqual(second["conversation_id"], first["conversation_id"])
        messages = app.list_messages(first["conversation_id"])
        self.assertGreaterEqual(len(messages), 3)
        self.assertNotIn("4111", " ".join(m["content"] for m in messages))
        self.assertTrue(any(m["role"] == "assistant" for m in messages))
        os.unlink(path)

    def test_lead_search(self):
        app, path = load_app()
        from lead_pipeline import create_lead, list_leads
        create_lead({"name":"Анна Петрова","email":"anna@example.com","company":"Acme","message":"Нужна интеграция"})
        create_lead({"name":"Иван","email":"ivan@example.com","company":"Other","message":"Консультация"})
        self.assertEqual(len(list_leads(search="anna@example.com")), 1)
        self.assertEqual(len(list_leads(search="Acme")), 1)
        self.assertEqual(len(list_leads(search="интеграция")), 1)
        self.assertEqual(len(list_leads(search="nobody")), 0)
        os.unlink(path)

    def test_stats_include_conversations_and_messages(self):
        app, path = load_app()
        app.answer_question("Как оформить возврат?")
        s = app.stats()
        self.assertGreaterEqual(s["conversations"], 1)
        self.assertGreaterEqual(s["messages"], 2)
        self.assertGreaterEqual(s["total"], 0)
        os.unlink(path)

    def test_operator_password_hash_and_roles(self):
        app, path = load_app()
        self.assertTrue(app.verify_password("secret", app.hash_password("secret")))
        self.assertFalse(app.verify_password("wrong", app.hash_password("secret")))
        self.assertEqual(app.ROLE_PERMISSIONS["viewer"], {"read"})
        self.assertIn("write", app.ROLE_PERMISSIONS["operator"])
        os.unlink(path)


if __name__ == '__main__':
    unittest.main()
