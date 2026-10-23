from flask import Flask, jsonify
from werkzeug.exceptions import RequestEntityTooLarge

from app.database import init_db
from app.routes import api


def create_app(test_config=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    if test_config:
        app.config.update(test_config)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_oversized_request(error):
        return jsonify(error="Request body is too large"), 400

    with app.app_context():
        init_db()

    app.register_blueprint(api)
    return app
