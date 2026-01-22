from dotenv import load_dotenv
import os

class Config:
    def __init__(self):
        load_dotenv()

        self.MONGO_STRING = os.getenv("MONGO_STRING")
        self.MONGO_DBNAME = os.getenv("MONGO_DBNAME")
        self.USERS_COLLECTION = os.getenv("USERS_COLLECTION")
        self.JWT_SECRET = os.getenv("JWT_SECRET")
        self.TOKEN_KEEPALIVE_MINUTES = os.getenv("TOKEN_KEEPALIVE_MINUTES")
        self.AUTH_LIMITER_PER_DAY = os.getenv("AUTH_LIMITER_PER_DAY")
        self.AUTH_LIMITER_PER_HOUR = os.getenv("AUTH_LIMITER_PER_HOUR")
        self.ADMIN_ID = os.getenv("ADMIN_ID")
        self.ADMIN_OTP_SECRET = os.getenv("ADMIN_OTP_SECRET")
        self.CHECKSUMS_COLLECTION = os.getenv("CHECKSUMS_COLLECTION")
        self.LICENSES_COLLECTION = os.getenv("LICENSES_COLLECTION")
        self.LICENSE_PUBLIC_KEY = os.getenv("LICENSE_PUBLIC_KEY")
        self.LICENSE_PRIVATE_KEY = os.getenv("LICENSE_PRIVATE_KEY")

        if any(var is None or var.strip() == '' for var in {self.MONGO_STRING}):
            exit()

config = Config()
