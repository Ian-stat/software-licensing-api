import pytest
import base64
from bson import ObjectId
import jwt
from config import config

from modules.validator import is_valid_objectid, is_valid_email, is_valid_username
from modules.license_generator import get_license, get_hardware_id, get_signed_license
from modules.authentication import is_admin, admin_only, authenticated, generate_token
from app import app
from datetime import datetime, timedelta, timezone

class TestValidator:
    def test_is_valid_objectid_returns_true(self):
        valid_id = str(ObjectId())
        assert is_valid_objectid(valid_id) == True
    
    def test_is_valid_objectid_returns_false(self):
        assert is_valid_objectid("invalid") == False
        assert is_valid_objectid("123") == False
        assert is_valid_objectid("") == False
        assert is_valid_objectid("zzzzzzzzzzzzzzzzzzzzzzz") == False
    
    def test_is_valid_email_returns_true(self):
        assert is_valid_email("user@example.com") == True
        assert is_valid_email("test123@domain.org") == True
        assert is_valid_email("admin@test.pl") == True
    
    def test_is_valid_email_returns_false(self):
        assert is_valid_email("invalid") == False
        assert is_valid_email("@example.com") == False
        assert is_valid_email("user@") == False
        assert is_valid_email("user@example") == False
        assert is_valid_email("User@Example.com") == False
        assert is_valid_email("user name@example.com") == False
    
    def test_is_valid_username_returns_true(self):
        assert is_valid_username("user123") == True
        assert is_valid_username("Admin") == True
        assert is_valid_username("TestUser") == True
    
    def test_is_valid_username_returns_false(self):
        assert is_valid_username("user-123") == False
        assert is_valid_username("user_123") == False
        assert is_valid_username("user 123") == False
        assert is_valid_username("user@123") == False
        assert is_valid_username("") == False

class TestLicenseGenerator:
    def test_get_license_returns_valid_license(self):
        license_key = get_license()
        parts = license_key.split("-")
        
        assert len(parts) == 4
        assert len(parts[0]) == 5
        assert len(parts[1]) == 5
        assert len(parts[2]) == 5
        assert len(parts[3]) == 5
        assert parts[0].isupper() and parts[0].isalpha()
        assert parts[1].isupper() and parts[1].isalpha()
        assert parts[2].isdigit()
        assert parts[3].isdigit()
    
    def test_get_license_returns_unique_license(self):
        licenses = [get_license() for _ in range(100)]
        assert len(licenses) == len(set(licenses))
    
    def test_get_hardware_id_returns_valid_base64(self):
        hardware_id = get_hardware_id("spec1", "spec2", "spec3", "spec4", "spec5")
        
        try:
            decoded = base64.b64decode(hardware_id)
            assert decoded == b"spec1|spec2|spec3|spec4|spec5"
        except Exception:
            pytest.fail("Hardware ID is not a valid base64 value.")
    
    def test_get_signed_license_returns_signed_license(self):
        license_key = "AAAAA-BBBBB-11111-22222"
        hardware_id = "dGVzdF9oYXJkd2FyZV9pZA=="
        
        signature = get_signed_license(license_key, hardware_id)
        
        try:
            base64.b64decode(signature)
        except Exception:
            pytest.fail("Signed license is not a valid base64 value.")
        
        assert len(signature) > 0

@pytest.fixture
def user_token():
    payload = {
        "user_id": "asdf",
        "expiry_date": str(datetime.now(timezone.utc) + timedelta(minutes=int(config.TOKEN_KEEPALIVE_MINUTES)))
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")

@pytest.fixture
def admin_token():
    payload = {
        "user_id": config.ADMIN_ID,
        "expiry_date": str(datetime.now(timezone.utc) + timedelta(minutes=int(config.TOKEN_KEEPALIVE_MINUTES)))
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")

class TestAuthentication:

    def test_is_admin_when_user_is_admin_returns_true(self, admin_token):
        with app.test_request_context(headers={"Authorization": f"Bearer {admin_token}"}):
            @is_admin
            def dummy_function(is_admin=False):
                return is_admin
        
            assert dummy_function() == True
    
    def test_is_admin_when_user_is_not_admin_returns_false(self, user_token):
        with app.test_request_context(headers={"Authorization": f"Bearer {user_token}"}):
            @is_admin
            def dummy_function(is_admin=False):
                return is_admin
        
            assert dummy_function() == False
    
    def test_admin_only_when_user_is_admin_returns_user_id(self, admin_token):
        with app.test_request_context(headers={"Authorization": f"Bearer {admin_token}"}):
            @admin_only
            def dummy_function(user_id=""):
                return user_id
        
            assert dummy_function() == config.ADMIN_ID
            
    def test_admin_only_when_user_is_not_admin_returns_401(self, user_token):
        with app.test_request_context(headers={"Authorization": f"Bearer {user_token}"}):
            @admin_only
            def dummy_function(user_id=""):
                return user_id
        
            data, code = dummy_function()

            assert isinstance(data["message"], str)
            assert code == 401
            
    def test_authenticated_when_no_authentication_header_returns_401(self):
        with app.test_request_context():
            @authenticated
            def dummy_function(user_id=""):
                return user_id
            
            data, code = dummy_function()
            
            assert isinstance(data["message"], str)
            assert code == 401
    
    def test_authenticated_when_authenticated_returns_user_id(self, user_token):
        with app.test_request_context(headers={"Authorization": f"Bearer {user_token}"}):
            @authenticated
            def dummy_function(user_id=""):
                return user_id
            
            assert isinstance(dummy_function(), str)
            
    def test_generate_token_returns_valid_jwt(self):
        token = generate_token("asdf")
        
        assert isinstance(token, str)
        assert token.count(".") == 2  # JWT ma 3 czesci