import pytest
from modules.authentication import generate_token
import bcrypt
from bson import ObjectId
from app import app
from config import config

@pytest.fixture
def db():
    from app import mongo_client

    yield mongo_client

    for name in mongo_client.list_collection_names():
        mongo_client[name].drop()

@pytest.fixture
def client():
    app.config["TESTING"] = True

    from modules.limiter import limiter
    limiter.enabled = False

    with app.test_client() as client:
        yield client

@pytest.fixture
def admin_headers(db):
    admin_id = ObjectId(config.ADMIN_ID)

    hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
    db[config.USERS_COLLECTION].insert_one({
        "_id": admin_id,
        "username": "admin",
        "email": "admin@test.com",
        "password": hashed,
        "role": "admin",
    })

    token = generate_token(str(admin_id))
    yield {"Authorization": f"Bearer {token}"}

@pytest.fixture
def user_headers(db):
    user_id = ObjectId()

    hashed = bcrypt.hashpw(b"user123", bcrypt.gensalt())
    db[config.USERS_COLLECTION].insert_one({
        "_id": user_id,
        "username": "basic_user",
        "email": "user@test.com",
        "password": hashed,
    })

    token = generate_token(str(user_id))
    yield {
        "Authorization": f"Bearer {token}",
        "user_id": str(user_id),
    }

class TestLogin:
    def test_login_when_valid_identity_returns_jwt(self, client, db):
        hashed = bcrypt.hashpw(b"secret", bcrypt.gensalt())
        db[config.USERS_COLLECTION].insert_one({
            "username": "tester",
            "password": hashed,
        })

        res = client.post("/auth", json={
            "username": "tester",
            "password": "secret",
        })

        assert res.status_code == 200
        assert "data" in res.json
        assert isinstance(res.json["data"], str)
        assert res.json["data"].count(".") == 2  # JWT ma 3 czesci


    def test_login_when_wrong_password_returns_401(self, client, db):
        hashed = bcrypt.hashpw(b"secret", bcrypt.gensalt())
        db[config.USERS_COLLECTION].insert_one({
            "username": "tester",
            "password": hashed,
        })

        res = client.post("/auth", json={
            "username": "tester",
            "password": "wrong",
        })

        assert res.status_code == 401


    def test_login_when_nonexistent_user_returns_401(self, client):
        res = client.post("/auth", json={
            "username": "ghost",
            "password": "password",
        })
        assert res.status_code == 401

class TestUsers:
    def test_create_user_when_authenticated_as_admin_succeeds(self, client, admin_headers, db):
        payload = {
            "username": "newstudent",
            "password": "123",
            "email": "student@uni.edu",
        }

        res = client.post("/users", json=payload, headers=admin_headers)
        assert res.status_code == 201

        user = db[config.USERS_COLLECTION].find_one({"username": "newstudent"})
        assert user is not None


    def test_create_user_when_unauthenticated_returns_401(self, client):
        res = client.post("/users", json={
            "username": "hacker",
            "password": "123",
            "email": "hack@evil.com",
        })
        assert res.status_code == 401


    def test_create_user_when_duplicate_user_returns_409(self, client, admin_headers):
        payload = {
            "username": "unique",
            "password": "123",
            "email": "u@u.com",
        }

        client.post("/users", json=payload, headers=admin_headers)
        res = client.post("/users", json=payload, headers=admin_headers)

        assert res.status_code == 409


    def test_delete_user_when_authenticated_as_admin_succeeds(self, client, admin_headers, db):
        user_id = ObjectId()
        db[config.USERS_COLLECTION].insert_one({
            "_id": user_id,
            "username": "todelete",
        })

        res = client.delete(f"/users/{user_id}", headers=admin_headers)
        assert res.status_code == 200
        assert db[config.USERS_COLLECTION].find_one({"_id": user_id}) is None


    def test_get_users_when_unauthenticated_returns_401(self, client):
        res = client.get("/users")
        assert res.status_code == 401


    def test_get_users_when_authenticated_as_admin_returns_users(self, client, admin_headers, db):
        db[config.USERS_COLLECTION].insert_one({
            "username": "extra_user",
            "email": "extra@test.com",
        })

        res = client.get("/users", headers=admin_headers)
        assert res.status_code == 200

        usernames = [u["username"] for u in res.json]
        assert "admin" in usernames
        assert "extra_user" in usernames

class TestLicenses:
    def test_generate_license_when_authenticated_as_admin_returns_license_key(self, client, admin_headers, user_headers, db):
        res = client.post(
            "/licenses",
            json={"user_id": user_headers["user_id"]},
            headers=admin_headers,
        )

        assert res.status_code == 201
        assert "data" in res.json

        key = res.json["data"]
        assert db[config.LICENSES_COLLECTION].find_one(
            {"license_key": key}
        ) is not None


    def test_generate_license_when_authenticated_as_user_returns_401(self, client, user_headers):
        res = client.post(
            "/licenses",
            json={"user_id": user_headers["user_id"]},
            headers={"Authorization": user_headers["Authorization"]},
        )
        assert res.status_code == 401


    def test_generate_license_when_unauthenticated_returns_401(self, client):
        res = client.post("/licenses", json={"user_id": str(ObjectId())})
        assert res.status_code == 401


    def test_generate_license_for_nonexistent_user_returns_404(self, client, admin_headers):
        res = client.post(
            "/licenses",
            json={"user_id": str(ObjectId())},
            headers=admin_headers,
        )
        assert res.status_code == 404
