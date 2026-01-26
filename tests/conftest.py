from unittest.mock import patch, MagicMock
import pytest
import mongomock

mock_settings = MagicMock()
mock_settings.MONGO_STRING = "mongodb://localhost:27017"
mock_settings.MONGO_DBNAME = "testdb"
mock_settings.USERS_COLLECTION = "users"
mock_settings.LICENSES_COLLECTION = "licenses"
mock_settings.CHECKSUMS_COLLECTION = "checksums"
mock_settings.JWT_SECRET = "test_secret"
mock_settings.ADMIN_ID = "000000000000000000000000"
mock_settings.ADMIN_OTP_SECRET = ""
mock_settings.TOKEN_KEEPALIVE_MINUTES = "15"
mock_settings.AUTH_LIMITER_PER_DAY = "9999"
mock_settings.AUTH_LIMITER_PER_HOUR = "9999"

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

mock_settings.LICENSE_PUBLIC_KEY = PUBLIC_KEY_PEM.decode("utf-8")
mock_settings.LICENSE_PRIVATE_KEY = PRIVATE_KEY_PEM.decode("utf-8")

patch("pymongo.MongoClient", mongomock.MongoClient).start()
patch("config.config", mock_settings).start()