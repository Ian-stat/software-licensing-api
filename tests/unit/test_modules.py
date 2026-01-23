import pytest
import jwt
import base64
from unittest.mock import patch
from bson import ObjectId

from modules.validator import is_valid_objectid, is_valid_email, is_valid_username
from modules.license_generator import get_license, get_hardware_id, get_signed_license
from modules.authentication import generate_token
from modules.healthcheck import healthcheck
from config import config

class TestValidator:
    def test_is_valid_objectid_correct(self):
        valid_id = str(ObjectId())
        assert is_valid_objectid(valid_id) == True
    
    def test_is_valid_objectid_incorrect(self):
        assert is_valid_objectid("invalid") == False
        assert is_valid_objectid("123") == False
        assert is_valid_objectid("") == False
        assert is_valid_objectid("zzzzzzzzzzzzzzzzzzzzzzz") == False
    
    def test_is_valid_email_correct(self):
        assert is_valid_email("user@example.com") == True
        assert is_valid_email("test123@domain.org") == True
        assert is_valid_email("admin@test.pl") == True
    
    def test_is_valid_email_incorrect(self):
        assert is_valid_email("invalid") == False
        assert is_valid_email("@example.com") == False
        assert is_valid_email("user@") == False
        assert is_valid_email("user@example") == False
        assert is_valid_email("User@Example.com") == False
        assert is_valid_email("user name@example.com") == False
    
    def test_is_valid_username_correct(self):
        assert is_valid_username("user123") == True
        assert is_valid_username("Admin") == True
        assert is_valid_username("TestUser") == True
    
    def test_is_valid_username_incorrect(self):
        assert is_valid_username("user-123") == False
        assert is_valid_username("user_123") == False
        assert is_valid_username("user 123") == False
        assert is_valid_username("user@123") == False
        assert is_valid_username("") == False

class TestLicenseGenerator:
    def test_get_license_format(self):
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
    
    def test_get_license_uniqueness(self):
        licenses = [get_license() for _ in range(100)]
        assert len(licenses) == len(set(licenses))
    
    def test_get_hardware_id_encoding(self):
        hardware_id = get_hardware_id("spec1", "spec2", "spec3", "spec4", "spec5")
        
        try:
            decoded = base64.b64decode(hardware_id)
            assert decoded == b"spec1|spec2|spec3|spec4|spec5"
        except Exception:
            pytest.fail("Hardware ID nie jest poprawnym Base64")
    
    def test_get_hardware_id_empty_specs(self):
        hardware_id = get_hardware_id("", "", "", "", "")
        decoded = base64.b64decode(hardware_id)
        assert decoded == b"||||"
    
    @patch('modules.license_generator.config')
    def test_get_signed_license(self, mock_config):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        mock_config.LICENSE_PRIVATE_KEY = private_pem.decode('utf-8')
        
        license_key = "AAAAA-BBBBB-11111-22222"
        hardware_id = "dGVzdF9oYXJkd2FyZV9pZA=="
        
        signature = get_signed_license(license_key, hardware_id)
        
        try:
            base64.b64decode(signature)
        except Exception:
            pytest.fail("Podpis nie jest poprawnym Base64")
        
        assert len(signature) > 0

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])