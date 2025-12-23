# The conftest.py file is a special file used by the pytest Python testing framework to manage and 
# share test configurations, fixtures, and custom hooks across multiple test files and directories. 
# It allows for centralized setup and teardown code, making tests cleaner and more maintainable. 


import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def app():
    # In-memory DB, no background scanner thread during tests
    return create_app(start_scanner=False, db_url="sqlite+pysqlite:///:memory:")


@pytest.fixture()
def client(app):
    return TestClient(app)