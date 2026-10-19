import os, tempfile
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/t.db"
import pytest
@pytest.fixture(autouse=True)
def _reset_rate_limits():
    from app import security; security._hits.clear(); yield
