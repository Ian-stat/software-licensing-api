import pytest
from app import app, mongo_client
from config import config
from bson import ObjectId
from modules.authentication import generate_token
import bcrypt
import pymongo

@pytest.fixture(autouse=True)
def clean_mongo_client():
    
    mongo_client = pymongo.MongoClient(config.MONGO_STRING)[config.MONGO_DBNAME]
    
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
def admin_headers():
    admin_id = ObjectId(config.ADMIN_ID)

    hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
    mongo_client[config.USERS_COLLECTION].insert_one({
        "_id": admin_id,
        "username": "admin",
        "email": "admin@test.com",
        "password": hashed,
        "role": "admin",
    })

    token = generate_token(str(admin_id))
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def user_headers():
    user_id = ObjectId()

    hashed = bcrypt.hashpw(b"user123", bcrypt.gensalt())
    mongo_client[config.USERS_COLLECTION].insert_one({
        "_id": user_id,
        "username": "basic_user",
        "email": "user@test.com",
        "password": hashed,
    })

    token = generate_token(str(user_id))
    return {
        "Authorization": f"Bearer {token}",
        "user_id": str(user_id),
    }

class TestUsers:
    @pytest.mark.xfail
    def test_create_user(self, client, admin_headers):
        payload = {
            "username": "newstudent",
            "password": "123",
            "email": "student@uni.edu",
        }

        res = client.post("/users", json=payload, headers=admin_headers)
        assert res.status_code == 201

        user = mongo_client[config.USERS_COLLECTION].find_one({"username": "newstudent"})
        assert user is not None
    
    @pytest.mark.xfail
    def test_delete_user(self, client, admin_headers):
        user_id = ObjectId()
        mongo_client[config.USERS_COLLECTION].insert_one({
            "_id": user_id,
            "username": "todelete",
        })

        res = client.delete(f"/users/{user_id}", headers=admin_headers)
        assert res.status_code == 200
        assert mongo_client[config.USERS_COLLECTION].find_one({"_id": user_id}) is None
    
    @pytest.mark.xfail
    def test_get_users(self, client, admin_headers):
        mongo_client[config.USERS_COLLECTION].insert_one({
            "username": "extra_user",
            "email": "extra@test.com",
        })

        res = client.get("/users", headers=admin_headers)
        assert res.status_code == 200

        usernames = [u["username"] for u in res.json]
        assert "admin" in usernames
        assert "extra_user" in usernames

class TestLicenses:
    @pytest.mark.xfail
    def test_generate_license(self, client, admin_headers, user_headers):
        res = client.post(
            "/licenses",
            json={"user_id": user_headers["user_id"]},
            headers=admin_headers,
        )

        assert res.status_code == 201
        assert "data" in res.json

        key = res.json["data"]
        assert mongo_client[config.LICENSES_COLLECTION].find_one(
            {"license_key": key}
        ) is not None