from unittest.mock import patch, MagicMock
import pytest
import sys

class TestingConfig:
    def __init__(self):
        self.MONGO_STRING = "mongodb://localhost:27017"
        self.MONGO_DBNAME = "testdb"
        self.USERS_COLLECTION = "users"
        self.LICENSES_COLLECTION = "licenses"
        self.CHECKSUMS_COLLECTION = "checksums"
        self.JWT_SECRET = "test_secret"
        self.ADMIN_ID = "000000000000000000000000"
        self.ADMIN_OTP_SECRET = ""
        self.TOKEN_KEEPALIVE_MINUTES = "15"
        self.AUTH_LIMITER_PER_DAY = "9999"
        self.AUTH_LIMITER_PER_HOUR = "9999"

        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        PRIVATE_KEY = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        PRIVATE_KEY_PEM = PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        PUBLIC_KEY = PRIVATE_KEY.public_key()
        PUBLIC_KEY_PEM = PUBLIC_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.LICENSE_PUBLIC_KEY = PUBLIC_KEY_PEM.decode("utf-8")
        self.LICENSE_PRIVATE_KEY = PRIVATE_KEY_PEM.decode("utf-8")

testing_config = TestingConfig()

mock_module = MagicMock()
mock_module.config = testing_config
sys.modules["config"] = mock_module