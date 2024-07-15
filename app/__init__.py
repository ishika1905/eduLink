from flask import Flask, current_app,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_restful import Api
from flask_mail import Mail
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from .config import Config
from pymongo import MongoClient
from loguru import logger
import datetime
import logging

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

# MongoDB connection and logger setup
client = MongoClient('mongodb://localhost:27017/')
db_mongo = client['flask_logs']
log_collection = db_mongo['logs']

class MongoDBHandler:
    def __init__(self, collection):
        self.collection = collection

    def write(self, message):
        if message.strip():
            log_entry = {
                "message": message,
                "timestamp": datetime.datetime.utcnow()
            }
            self.collection.insert_one(log_entry)

    def flush(self):
        pass
    
mongo_handler = MongoDBHandler(log_collection)
logger.add(mongo_handler.write, format="{time} {level} {message}")

@login_manager.user_loader
def load_user(email):
    from .models import User
    return User.query.filter_by(email=email).first()

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

# Import routes here to avoid circular import
from . import routes

# Error handling
@app.errorhandler(Exception)
def handle_error(e):
    current_app.logger.error(f"An error occurred: {str(e)}")
    return jsonify({'message': 'Internal server error'}), 500

# Configure logging
logging.basicConfig(level=logging.INFO)

