import pytest
from app import app

@pytest.fixture
def client():
    return app.test_client()

# demko
def test_health(client):
    response = client.get("/")
    assert response.status_code == 200