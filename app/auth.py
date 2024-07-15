from flask import jsonify, request, render_template, url_for
from app import app, db, bcrypt, mail
from app.models import User
from app.forms import RegisterForm, LoginForm
from flask_jwt_extended import create_access_token, get_jwt_identity, unset_jwt_cookies
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from app.decorater import token_in_database_required
from loguru import logger

# Adjust this tolerance window as needed (in seconds)
TOKEN_TOLERANCE_SECONDS = 30

def verify_token_issued_at(token):
    current_time = datetime.utcnow()
    issued_at = token.get('iat', 0)
    token_issued_at = datetime.utcfromtimestamp(issued_at)

    if current_time < token_issued_at - timedelta(seconds=TOKEN_TOLERANCE_SECONDS):
        return False

    return True

def google_auth():
    try:
        data = request.get_json()
        if not data or 'access_token' not in data:
            return jsonify({'message': 'No data received or invalid JSON format'}), 400

        token = data.get('access_token')

        try:
            id_info = id_token.verify_oauth2_token(token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
            if not verify_token_issued_at(id_info):
                return jsonify({'message': 'Token used too early'}), 400

            user = User.query.filter_by(email=id_info['email']).first()
            if not user:
                user = User(name=id_info['name'], email=id_info['email'], confirmed=True)
                db.session.add(user)

            access_token = create_access_token(identity=user.email)
            user.access_token = access_token
            db.session.commit()

            logger.info(f"Login successful: User '{user.email}' logged in")
            return jsonify({'message': 'Login successful', 'access_token': access_token, 'user': {'name': user.name, 'email': user.email}}), 200

        except ValueError as e:
            logger.error(f"Error verifying token: {str(e)}")
            return jsonify({'message': 'Invalid token'}), 400

    except Exception as e:
        logger.error(f"Error during Google auth: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

def get_access_token():
    try:
        email = request.args.get('email')

        if not email:
            return jsonify({'message': 'Email is required as a query parameter'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        if not user.access_token:
            return jsonify({'message': 'Access token not found for the user'}), 404

        logger.info(f"Access token retrieved for user: {user.email}")
        return jsonify({'email': user.email, 'access_token': user.access_token}), 200

    except Exception as e:
        logger.error(f"Error retrieving access token: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@token_in_database_required
def set_password():
    try:
        current_user_email = get_jwt_identity()

        data = request.get_json()
        if not data or 'password' not in data or 'confirm_password' not in data:
            return jsonify({'message': 'Password and confirm password are required'}), 400

        password = data['password']
        confirm_password = data['confirm_password']

        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400

        user = User.query.filter_by(email=current_user_email).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        user.set_password(password)  # Assuming User model has a method set_password to hash and set the password
        db.session.commit()

        logger.info(f"Password set successfully for user: {user.email}")
        return jsonify({'message': 'Password set successfully'}), 200

    except Exception as e:
        logger.error(f"Error setting password: {str(e)}")
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except Exception as e:
        return None
    return email

def confirm_email(token):
    email = confirm_token(token)
    if not email:
        return jsonify({'message': 'Invalid or expired token. Please try again.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    if user.confirmed:
        logger.info(f"Email confirmed for user: {user.email}")
        return render_template('verify_page.html', url=url_for('login')), 200

    user.confirmed = True
    user.confirmed_on = datetime.utcnow()
    db.session.commit()

    logger.info(f"Email confirmed and updated for user: {user.email}")
    return render_template('verify_page.html', url=url_for('login')), 200

def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data received or invalid JSON format'}), 400

        form = RegisterForm(data=data)

        # Extract form data before validation to handle password mismatch separately
        name = form.name.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400

        if form.validate():
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                return jsonify({'message': 'User already exists'}), 400

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(name=name, email=email, password=hashed_password, confirmed=False)

            db.session.add(new_user)
            db.session.commit()

            confirm_email(new_user.email)  # Assuming this sends a confirmation email
            logger.info(f"User registered successfully: {email}")
            return jsonify({'message': 'User registered successfully'}), 200

        else:
            errors = form.errors
            return jsonify({'message': 'Validation failed', 'errors': errors}), 400

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error registering user: {e}")
        return jsonify({'message': 'Error registering user'}), 500

def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data received or invalid JSON format'}), 400

        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'Invalid credentials'}), 401

        try:
            # Attempt to hash the password and compare
            if bcrypt.check_password_hash(user.password, password):
                pass
            else:
                return jsonify({'message': 'Invalid credentials'}), 401
        except ValueError:
            # If ValueError occurs, the stored password is in plain text
            if user.password == password:
                # Hash the password and update the database
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                user.password = hashed_password
            else:
                return jsonify({'message': 'Invalid credentials'}), 401

        access_token = create_access_token(identity=email)
        user.access_token = access_token  # Update user's access token in the database

        db.session.commit()
        logger.info(f"Password hashed and access token set for user {user.email}")
        return jsonify({'message': 'Login successful', 'access_token': access_token}), 200

    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@token_in_database_required
def logout():
    try:
        current_user_email = get_jwt_identity()
        logger.debug(f"User {current_user_email} logging out.")

        user = User.query.filter_by(email=current_user_email).first()
        if user:
            user.access_token = None
            db.session.commit()

        resp = jsonify({'message': 'Logged out successfully'})
        unset_jwt_cookies(resp)
        logger.debug("User logged out successfully.")
        return resp, 200

    except Exception as e:
        logger.error(f"Error during logout: {e}")
        return jsonify({'message': 'Internal server error'}), 500
