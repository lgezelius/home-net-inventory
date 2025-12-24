# The conftest.py file is a special file used by the pytest Python testing framework to manage and 
# share test configurations, fixtures, and custom hooks across multiple test files and directories. 
# It allows for centralized setup and teardown code, making tests cleaner and more maintainable. 

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

@pytest.fixture()
def app():
    app = create_app(start_scanner=False, db_url="sqlite+pysqlite:///:memory:")
    try:
        yield app
    finally:
        # StaticPool keeps a connection open; dispose closes it cleanly.
        engine = getattr(app.state, "engine", None)
        if engine is not None:
            engine.dispose()

@pytest.fixture()
def client(app):
    # Context manager guarantees the client is closed
    with TestClient(app) as c:
        yield c