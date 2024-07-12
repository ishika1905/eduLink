from flask import jsonify, request, render_template,session
from app import app,db, bcrypt, mail, token_in_database_required
from app.models import User
from app.forms import RegisterForm, LoginForm
from flask_jwt_extended import create_access_token, get_jwt_identity, unset_jwt_cookies
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from flask import url_for
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

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
    data = request.get_json()
    print("Received data:", data)
    if not data or 'access_token' not in data:
        return jsonify({'message': 'No data received or invalid JSON format'}), 400

    token = data.get('access_token')
    print("Received token:", token)  

    try:
        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
        print("ID Info:", id_info) 
        if not verify_token_issued_at(id_info):
            return jsonify({'message': 'Token used too early'}), 400

        # Check if user already exists
        user = User.query.filter_by(email=id_info['email']).first()
        if not user:
            # Create a new user
            user = User(name=id_info['name'], email=id_info['email'], confirmed=True)
            db.session.add(user)

        # Generate access token
        access_token = create_access_token(identity=user.email)
        
        # Update user's access token in the database
        user.access_token = access_token
        db.session.commit()

        return jsonify({'message': 'Login successful', 'access_token': access_token, 'user': {'name': user.name, 'email': user.email}}), 200

    except ValueError as e:
        print("Error verifying token:", e)
        return jsonify({'message': 'Invalid token'}), 400

def get_access_token():
    email = request.args.get('email')

    if not email:
        return jsonify({'message': 'Email is required as a query parameter'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Example assuming `access_token` is a field in the User model
    if not user.access_token:
        return jsonify({'message': 'Access token not found for the user'}), 404

    return jsonify({'email': user.email, 'access_token': user.access_token}), 200
 
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

        return jsonify({'message': 'Password set successfully'}), 200

    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        return jsonify({'message': 'Invalid or expired token. Please try again.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    if user.confirmed:
        return render_template('verify_page.html', url=url_for('login')), 200

    # Mark email as confirmed and update confirmed_on timestamp
    user.confirmed = True
    user.confirmed_on = datetime.utcnow()
    db.session.commit()
    
    return render_template('verify_page.html', url=url_for('login')), 200

def register():
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
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'User already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password, confirmed=False)
        db.session.add(new_user)

        try:
            db.session.commit()
            send_verification_email(email)
            return jsonify({'message': 'User registered successfully'}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error registering user: {e}")
            return jsonify({'message': 'Error registering user'}), 500
    else:
        errors = form.errors
        return jsonify({'message': 'Validation failed', 'errors': errors}), 400

def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data received or invalid JSON format'}), 400

    form = LoginForm(data=data)
    if form.validate():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=email)
            user.access_token = access_token  # Update user's access token in the database
            try:
                db.session.commit()
                return jsonify({'message': 'Login successful', 'access_token': access_token}), 200
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error committing access token for user {user.email}: {e}")
                return jsonify({'message': 'Internal server error'}), 500
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    else:
        errors = form.errors
        return jsonify({'message': 'Validation failed', 'errors': errors}), 400

# Error handling
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error(f"An error occurred: {str(e)}")
    return jsonify({'message': 'Internal server error'}), 500


@token_in_database_required
def logout():
    try:
        current_user_email = get_jwt_identity()
        app.logger.debug(f"User {current_user_email} logging out.")

        user = User.query.filter_by(email=current_user_email).first()
        if user:
            user.access_token = None
            db.session.commit()

        resp = jsonify({'message': 'Logged out successfully'})
        unset_jwt_cookies(resp)
        app.logger.debug("User logged out successfully.")
        return resp, 200

    except Exception as e:
        app.logger.error(f"Error during logout: {e}")
        return jsonify({'message': 'Internal server error'}), 500