import sys
import os
import pytest
import json
import mongomock
import bcrypt
from unittest.mock import patch, MagicMock

test_env = {
    'MONGO_STRING': 'mongodb://localhost:27017',
    'MONGO_DBNAME': 'test_db',
    'USERS_COLLECTION': 'users',
    'JWT_SECRET': 'secret_test_key',
    'TOKEN_KEEPALIVE_MINUTES': '30',
    'AUTH_LIMITER_PER_DAY': '100',
    'AUTH_LIMITER_PER_HOUR': '10',
    'ADMIN_ID': '507f1f77bcf86cd799439011',
    'ADMIN_OTP_SECRET': 'test_otp',
    'CHECKSUMS_COLLECTION': 'checksums',
    'LICENSES_COLLECTION': 'licenses',
    'LICENSE_PUBLIC_KEY': 'test_public_key',
    'LICENSE_PRIVATE_KEY': 'test_private_key'
}

os_getenv_patcher = patch('os.getenv', side_effect=lambda key, default=None: test_env.get(key, default))
mongoclient_patcher = patch('pymongo.MongoClient', side_effect=mongomock.MongoClient)

os_getenv_patcher.start()
mongoclient_patcher.start()

class MockLimiter:
    def limit(self, *args, **kwargs):
        def decorator(f):
            return f
        return decorator
    
    def exempt(self, f):
        return f
    
    def init_app(self, app):
        pass

sys.modules['modules.limiter'] = MagicMock()
sys.modules['modules.limiter'].limiter = MockLimiter()
sys.modules['modules.limiter'].init_limiter = MagicMock()
sys.modules['dotenv'] = MagicMock()

from app import app, mongo_client
from config import config
from modules.authentication import generate_token

config.USERS_COLLECTION = "users"
config.LICENSES_COLLECTION = "licenses"
config.CHECKSUMS_COLLECTION = "checksums"
config.JWT_SECRET = "secret_test_key"
config.ADMIN_ID = "507f1f77bcf86cd799439011"
config.MONGO_DBNAME = "test_db"

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def db():
    try:
        mongo_client[config.USERS_COLLECTION].delete_many({})
        mongo_client[config.LICENSES_COLLECTION].delete_many({})
        mongo_client[config.CHECKSUMS_COLLECTION].delete_many({})
    except:
        pass
    return mongo_client

@pytest.fixture
def admin_headers(db):
    user_id = config.ADMIN_ID
    hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
    
    db[config.USERS_COLLECTION].insert_one({
        "_id": mongomock.ObjectId(user_id),
        "username": "admin",
        "email": "admin@test.com",
        "password": hashed
    })
    
    token = generate_token(user_id)
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture
def user_headers(db):
    user_id = "607f1f77bcf86cd799439022"
    hashed = bcrypt.hashpw(b"user123", bcrypt.gensalt())
    
    db[config.USERS_COLLECTION].insert_one({
        "_id": mongomock.ObjectId(user_id),
        "username": "basic_user",
        "email": "user@test.com",
        "password": hashed
    })
    
    token = generate_token(user_id)
    return {'Authorization': f'Bearer {token}', 'user_id': user_id}


def test_health(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json == {'message': 'API is up and running!'}

def test_login_success(client, db):
    hashed = bcrypt.hashpw(b"secret", bcrypt.gensalt())
    db["users"].insert_one({"username": "tester", "password": hashed})
    response = client.post("/auth", json={"username": "tester", "password": "secret"})
    assert response.status_code == 200
    assert "token" in response.json['message'].lower()
    assert response.json['data'] is not None

def test_login_fail(client):
    response = client.post("/auth", json={"username": "ghost", "password": "wrong_password"})
    assert response.status_code == 401

def test_create_user_as_admin(client, admin_headers, db):
    payload = {"username": "newstudent", "password": "123", "email": "student@uni.edu"}

    response = client.post("/users", json=payload, headers=admin_headers)

    assert response.status_code == 201
    assert db["users"].find_one({"username": "newstudent"}) is not None

def test_get_users_unauthorized(client):
    response = client.get("/users")
    assert response.status_code == 401

def test_checksum_lifecycle(client, admin_headers):
    payload = {"checksum": "abc-123-hash", "software_version": "v1.0"}
    client.post("/checksums", json=payload, headers=admin_headers)
    response = client.get("/checksums", headers=admin_headers)
    data = response.json
    assert len(data) == 1
    assert data[0]['checksum'] == "abc-123-hash"