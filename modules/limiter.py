from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import config

limiter = Limiter(get_remote_address,
    storage_uri = config.MONGO_STRING,
    default_limits = None,
    strategy = "fixed-window")

def init_limiter(app):
    limiter.init_app(app)
    
def stop_limiter():
    limiter.enabled = False