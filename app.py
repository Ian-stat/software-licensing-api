from config import config
from flask import Flask
from flask_restful import Api
from pymongo import MongoClient
from config import config
from modules.limiter import init_limiter

app = Flask(__name__)
api = Api(app)
mongo_client = MongoClient(config.MONGO_STRING)[config.MONGO_DBNAME]

init_limiter(app)

from modules.healthcheck import healthcheck
from routes.users import users
from routes.auth import auth
from routes.licenses import licenses
from routes.activate import activate
from routes.checksums import checksums

api.add_resource(healthcheck, "/")
api.add_resource(users, "/users", "/users/<string:requested_user_id>", "/users/<string:requested_user_id>/<string:requested_user_detail>", resource_class_args=(mongo_client, ))
api.add_resource(licenses, "/licenses", "/licenses/<string:license_id>", "/licenses/<string:license_id>/<string:requested_license_detail>", resource_class_args=(mongo_client, ))
api.add_resource(checksums, "/checksums", "/checksums/<string:checksum_id>", "/checksums/<string:checksum_id>/<string:requested_checksum_detail>", resource_class_args=(mongo_client, ))
api.add_resource(auth, "/auth", resource_class_args=(mongo_client, ))
api.add_resource(activate, "/activate", resource_class_args=(mongo_client, ))

@app.errorhandler(404)
def not_found(e):
    return {'message': 'Requested URL was not found.'}, 404

if __name__ == "__main__":
    app.run(ssl_context='adhoc', debug=True)