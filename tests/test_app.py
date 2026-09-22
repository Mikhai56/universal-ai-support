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


if __name__ == '__main__':
    unittest.main()
