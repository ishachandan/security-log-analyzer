"""
Security Log Analyzer - Main Entry Point
Production-ready Flask application with RAG pipeline
"""
from flask import Flask
from flask_cors import CORS
from app.api.routes import api_bp
from app.auth.routes import auth_bp
from app.auth import AuthManager
from config import settings
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app():
    """
    Application factory pattern
    Creates and configures the Flask application
    """
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    app = Flask(__name__, template_folder=template_dir)
    
    # Enable CORS
    CORS(app)
    
    # Configuration
    app.config['MAX_CONTENT_LENGTH'] = settings.MAX_UPLOAD_SIZE
    
    # Initialize authentication
    jwt_secret = os.getenv('JWT_SECRET', settings.JWT_SECRET)
    auth_manager = AuthManager(
        db_path=os.path.join('data', 'users.db'),
        jwt_secret=jwt_secret
    )
    app.config['AUTH_MANAGER'] = auth_manager
    logger.info("Authentication system initialized")
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp, url_prefix=settings.API_PREFIX)
    
    logger.info("Security Log Analyzer initialized successfully")
    logger.info(f"Registered routes: {[rule.rule for rule in app.url_map.iter_rules()]}")
    
    return app


def main():
    """
    Main entry point
    Starts the Flask development server
    """
    app = create_app()
    
    logger.info(f"Starting server on {settings.FLASK_HOST}:{settings.FLASK_PORT}")
    logger.info(f"Health check: http://{settings.FLASK_HOST}:{settings.FLASK_PORT}{settings.API_PREFIX}/health")
    logger.info(f"Auth endpoints: http://{settings.FLASK_HOST}:{settings.FLASK_PORT}/api/auth/login")
    
    app.run(
        host=settings.FLASK_HOST,
        port=settings.FLASK_PORT,
        debug=settings.FLASK_DEBUG
    )


if __name__ == "__main__":
    main()
