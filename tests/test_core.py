import os, tempfile, unittest, json, time, hmac, hashlib

class SupportPilotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.NamedTemporaryFile(delete=False)
        cls.tmp.close()
        os.environ["DB_PATH"]=cls.tmp.name
        os.environ["DATABASE_URL"]=""
        import app
        cls.app=app
        app.init_db()
        app.init_commercial_db()

    @classmethod
    def tearDownClass(cls):
        try: os.unlink(cls.tmp.name)
        except OSError: pass

    def test_password_policy(self):
        self.app.validate_password("StrongPass123")
        with self.assertRaises(ValueError): self.app.validate_password("weak")

    def test_company_registration_and_member(self):
        cid=self.app.commercial_register("Test Company","owner@test.example","StrongPass123")
        members=self.app.list_company_members(cid)
        self.assertEqual(len(members),1)
        self.assertEqual(members[0]["role"],"owner")
        token,who=self.app.commercial_login("owner@test.example","StrongPass123")
        self.assertTrue(token)
        self.assertEqual(who["member_role"],"owner")

    def test_kb_and_channel_tenant_data(self):
        cid=self.app.commercial_register("KB Company","kb@test.example","StrongPass123")
        self.assertTrue(self.app.create_company_kb(cid,"Delivery","Delivery takes 2 days","internal"))
        self.assertEqual(self.app.company_kb_items(cid)[0]["title"],"Delivery")
        self.app.add_company_channel(cid,"web","Website")
        self.assertEqual(self.app.company_usage(cid)["channels"]["used"],1)
        with self.assertRaises(ValueError): self.app.add_company_channel(cid,"web","Second")

    def test_permissions(self):
        cid=self.app.commercial_register("Role Company","role@test.example","StrongPass123")
        self.assertTrue(self.app.company_permission(cid,"role@test.example","manage"))\n        conn=self.app.db(); conn.execute("UPDATE companies SET plan=?",("starter",)); conn.commit(); conn.close()
        self.app.create_company_invitation({"id":cid,"owner_email":"role@test.example","member_email":"role@test.example"},"viewer@test.example","viewer")
        token= self.app.list_company_invitations(cid)[0]
        self.assertEqual(token["role"],"viewer")

    def test_stripe_signature(self):
        secret="whsec_test"
        payload=b'{"type":"checkout.session.completed","data":{"object":{"metadata":{"company_id":"x","plan":"starter"}}}}'
        ts=str(int(time.time()))
        sig=ts+"."+payload.decode()
        digest=hmac.new(secret.encode(),sig.encode(),hashlib.sha256).hexdigest()
        self.assertTrue(self.app.stripe_signature_valid(payload,"t="+ts+",v1="+digest,secret))
        self.assertFalse(self.app.stripe_signature_valid(payload,"t="+ts+",v1=bad",secret))

if __name__=="__main__": unittest.main()
