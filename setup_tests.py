from pymongo import MongoClient
import bcrypt
from modules.validator import is_valid_username
from config import config
import os

mongo_client: MongoClient = None
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

if not is_valid_username(ADMIN_USERNAME):
    raise Exception("[ERROR] Invalid username.")

try:
    mongo_client = MongoClient(config.MONGO_STRING)[config.MONGO_DBNAME]
    mongo_client.command("ping")
except Exception as e:
    print(f"\n[ERROR] An error occured while connecting to a MongoDB server. {e}\n")

try:
    user = mongo_client[config.USERS_COLLECTION].find_one({"username":ADMIN_USERNAME})
    if not user:
        hashed_password = bcrypt.hashpw(bytes(ADMIN_PASSWORD, 'utf-8'), bcrypt.gensalt())
        admin = mongo_client[config.USERS_COLLECTION].insert_one({"username": ADMIN_USERNAME, "password": hashed_password})
        os.environ["ADMIN_ID"] = str(admin.inserted_id)
    else:
        print("\n[ERROR] User with that name already exists.")
except Exception as e:
    print(f"\n[ERROR] An errour occured while creating admin user. {e}\n")