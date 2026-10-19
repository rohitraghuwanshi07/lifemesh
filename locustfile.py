# Real load test against a running stack:  pip install locust && locust -f locustfile.py --host http://localhost:8000
from locust import HttpUser, task, between
class U(HttpUser):
    wait_time = between(0.5, 2)
    def on_start(self):
        import uuid; r = self.client.post("/auth/register", json={"email": f"{uuid.uuid4().hex}@load.test", "password": "correct-horse-1"}); self.client.headers["x-csrf-token"] = self.client.cookies["csrf"]
    @task(3)
    def tasks(self): self.client.get("/tasks")
    @task
    def brief(self): self.client.get("/briefing")
    @task
    def ask(self): self.client.post("/ask", json={"question": "what needs attention"})
