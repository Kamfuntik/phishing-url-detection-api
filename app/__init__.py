"""
app/__init__.py
Application factory for the Phishing URL Detection API.
"""

from typing import Optional, Type
from flask import Flask

from app.config import Config
from app.errors import register_error_handlers
from app.extensions import limiter
from app.routes.health import health_bp


def create_app(config_class: Type[Config] = Config) -> Flask:
    """
    Instantiates and configures the Flask application using the factory pattern
    so isolated instances can be created for unit and integration testing.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize rate limiter
    limiter.init_app(app)

    # Register centralized JSON error handlers
    register_error_handlers(app)

    # Register route blueprints
    app.register_blueprint(health_bp)

    return app