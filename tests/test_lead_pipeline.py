import os
import tempfile
import unittest

import app
from lead_pipeline import create_lead, init_leads, list_leads, update_lead

class LeadPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        os.environ["DB_PATH"]=self.tmp.name
        app.DB_PATH=self.tmp.name
        conn=app.db()
        app.init_db()
        conn=app.db()
        init_leads(conn)
        conn.commit()
        conn.close()

    def tearDown(self):
        try: os.unlink(self.tmp.name)
        except FileNotFoundError: pass

    def test_create_and_update_lead(self):
        lead_id=create_lead({"name":"Test","email":"test@example.com","company":"Example","message":"Need a quote"})
        rows=list_leads()
        self.assertEqual(rows[0]["id"],lead_id)
        self.assertEqual(rows[0]["status"],"NEW")
        self.assertTrue(update_lead(lead_id,{"status":"QUALIFIED","qualification_reason":"Relevant request"}))
        self.assertEqual(list_leads()[0]["status"],"QUALIFIED")

    def test_redacts_card_data_in_phone_and_generated_fields(self):
        lead_id = create_lead({
            "name":"Test","email":"test@example.com",
            "phone":"4111 1111 1111 1111",
            "message":"Hello",
            "generated_email":"Card 4111 1111 1111 1111"
        })
        row = list_leads()[0]
        self.assertEqual(row["id"], lead_id)
        self.assertNotIn("4111 1111 1111 1111", row["phone"])
        self.assertNotIn("4111 1111 1111 1111", row["generated_email"])

    def test_reject_invalid_email(self):
        with self.assertRaises(ValueError):
            create_lead({"name":"Test","email":"not-an-email","message":"Hello"})

    def test_redacts_card_data(self):
        lead_id = create_lead({"name":"Test","email":"test@example.com","message":"Card 4111 1111 1111 1111"})
        row = list_leads()[0]
        self.assertEqual(row["id"], lead_id)
        self.assertNotIn("4111 1111 1111 1111", row["message"])

if __name__=="__main__":
    unittest.main()
