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


if __name__ == '__main__':
    unittest.main()
