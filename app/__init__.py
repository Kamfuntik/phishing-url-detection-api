"""
app/__init__.py
Application factory for the Phishing URL Detection API.
"""

from typing import Type
from flask import Flask

from app.config import Config
from app.errors import register_error_handlers
from app.extensions import limiter
from app.middleware import register_middleware
from app.routes.analyze import analyze_bp
from app.routes.health import health_bp


def create_app(config_class: Type[Config] = Config) -> Flask:
    """
    Instantiates and configures the Flask application using the factory pattern
    so isolated instances can be created for unit and integration testing.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize rate limiter and request tracing middleware
    limiter.init_app(app)
    register_middleware(app)

    # Register centralized JSON error handlers
    register_error_handlers(app)

    # Register route blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(analyze_bp)

    return app
