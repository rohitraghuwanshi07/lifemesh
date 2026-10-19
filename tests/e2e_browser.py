"""Real-browser test: python tests/e2e_browser.py (needs `playwright install chromium`). Starts the API on :8765 with a temp SQLite DB."""
import os, subprocess, sys, tempfile, time, urllib.request
env = {**os.environ, "DATABASE_URL": f"sqlite:///{tempfile.mkdtemp()}/e.db"}
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8765", "--log-level", "warning"], env=env, cwd=os.path.dirname(os.path.dirname(__file__)))
try:
    for _ in range(50):
        try: urllib.request.urlopen("http://127.0.0.1:8765/health"); break
        except Exception: time.sleep(.2)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(); pg = b.new_page(); errs = []; pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto("http://127.0.0.1:8765/"); pg.click("a:has-text('Open the app') >> nth=0"); pg.wait_for_url("**/app/")
        pg.fill('input[type=email]', "ui@test.dev"); pg.fill('input[type=password]', "correct-horse-1"); pg.click("text=Create account")
        pg.wait_for_selector("text=Nothing synced yet")
        pg.click("role=tab[name='Documents']"); pg.set_input_files("input[type=file]", files=[{"name": "n.txt", "mimeType": "text/plain", "buffer": b"Interview on 30 Dec 2030 10:00 AM."}])
        pg.click("button:has-text('Upload')"); pg.wait_for_function("document.getElementById('msg').textContent.length>0"); print("msg:", pg.inner_text("#msg")); pg.wait_for_selector("#msg:has-text('1 item')")
        pg.click("role=tab[name='Tasks']"); pg.click("button:has-text('Approve')"); pg.wait_for_timeout(800); print("after approve:", repr(pg.inner_text("#app")[:400]), "| msg:", pg.inner_text("#msg")); pg.wait_for_selector("button:has-text('Mark done')")
        pg.click("role=tab[name='Graph']"); pg.wait_for_selector("svg[aria-label='Context graph'] circle"); pg.click("svg g[aria-label^='fact']"); pg.wait_for_selector("text=Evidence")
        pg.click("role=tab[name='Inbox']"); pg.wait_for_selector("text=No emails yet"); pg.click("role=tab[name='Privacy']"); pg.wait_for_selector("text=Activity log")
        pg.click("role=tab[name='Ask']"); pg.fill('input[aria-label=Question]', "when is my next interview"); pg.click("button.pri:has-text('Ask')"); pg.wait_for_selector("text=Next recorded interview")
        pg.click("role=tab[name='Integrations']"); pg.click("text=Connect Google"); pg.wait_for_selector("text=not configured")  # honest failure, nothing marked connected
        assert pg.locator("text=No accounts connected").count() == 1 and not errs, errs
        print("browser e2e: PASS"); b.close()
finally: srv.terminate()
