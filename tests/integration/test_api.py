import pytest
import requests
from app import app


@pytest.fixture
def app():
    yield app
    
def test_health():
    response = requests.get("/")
    assert response.status_code == 200