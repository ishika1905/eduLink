from flask import Flask, jsonify,request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
import logging
from flask_login import LoginManager
from flask_restful import Api
from flask_mail import Mail
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from datetime import timedelta
from .config import Config

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
api = Api(app)
mail = Mail(app)
migrate = Migrate(app, db)

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=None,  # No client secret for iOS
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    client_kwargs={'scope': 'openid profile email'},
)

# Load user callback for Flask-Login
@login_manager.user_loader
def load_user(email):
    from app.models import User
    return User.query.filter_by(email=email).first()
mail = Mail(app)  

from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from functools import wraps
from flask import jsonify, request
from app.models import User
from flask_login import login_user, current_user
from app import db
# Decorator to verify JWT token and check if it exists in the database
def token_in_database_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_email = get_jwt_identity()

            # Fetch the token from the headers
            token = request.headers.get('Authorization', None)
            if token is None:
                return jsonify({'message': 'Token is missing'}), 401

            # Remove "Bearer " prefix if present
            if token.startswith('Bearer '):
                token = token.split(" ")[1]

            # Check if the token exists in the database
            user = User.query.filter_by(email=current_user_email, access_token=token).first()
            if not user:
                return jsonify({'message': 'Invalid token or user not found'}), 401

            login_user(user)
        except Exception as e:
            return jsonify({'message': 'Token verification failed', 'error': str(e)}), 401
        return fn(*args, **kwargs)
    return wrapper

# Error handling
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error(f"An error occurred: {str(e)}")
    return jsonify({'message': 'Internal server error'}), 500

# Import routes at the end to avoid circular imports
from app import routes

# Configure logging
logging.basicConfig(level=logging.INFO)
