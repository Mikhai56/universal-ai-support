        self.assertTrue(app.create_operator("strong@example.com", "Strongpass1234", "operator"))
        conn = app.db()
        stored = conn.execute("SELECT password_hash FROM operators WHERE email=?", ("strong@example.com",)).fetchone()["password_hash"]
        conn.close()
        self.assertTrue(app.verify_password("Strongpass1234", stored))