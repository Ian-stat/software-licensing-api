from functools import wraps
from flask_restful import Resource, request
from datetime import datetime, timedelta, timezone
from config import config
import os
import jwt

"""
Only allow authenticated users, verify the token
"""
def authenticated(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
            expiry_date = payload["expiry_date"]

            if datetime.now(timezone.utc) > datetime.fromisoformat(expiry_date):
                raise Exception
        except:
            return {"message":"Access unauthorized."}, 401
        
        return f(user_id=payload["user_id"], *args, **kwargs)
    return decorated

"""
Detect admin user and provide a boolean for logic
"""
def is_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers["Authorization"].split(" ")[1]
            payload = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
            if payload["user_id"] != config.ADMIN_ID:
                raise Exception
        except Exception:
            return f(is_admin=False, *args, **kwargs)

        return f(is_admin=True, *args, **kwargs)
    return decorated

"""
Only allow admin user authenticated with a valid token to pass
"""
def admin_only(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = None
            if "Authorization" in request.headers:
                auth_header = request.headers["Authorization"]
                if auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]

            payload = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
            if payload["user_id"] != config.ADMIN_ID:
                raise Exception
            expiry_date = payload["expiry_date"]
            if datetime.now(timezone.utc) > datetime.fromisoformat(expiry_date):
                raise Exception
        except Exception:
            return {"message":"Access unauthorized."}, 401

        return f(user_id=payload["user_id"], *args, **kwargs)
    return decorated

"""
Generate a JWT token
- each token is assigned to a specific user id
- each token has an expiry date
"""
def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "expiry_date": str(datetime.now(timezone.utc) + timedelta(minutes=int(config.TOKEN_KEEPALIVE_MINUTES)))
    }
    token = jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")
    return token





        
