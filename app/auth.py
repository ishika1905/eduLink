from flask import jsonify, request, session, render_template_string, url_for
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
import random
from datetime import datetime, timedelta, timezone

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

def generate_otp():
    return str(random.randint(10000, 99999))

# Function to send OTP via email
def send_otp_email(email, otp):
    html_body = render_template_string(
        """
        <div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
            <div style="margin:50px auto;width:70%;padding:20px 0">
                <div style="border-bottom:1px solid #eee">
                    <a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600">EduLink</a>
                </div>
                <p style="font-size:1.1em">Welcome to EduLink</p>
                <p>Thank you for registering with EduLink. We are excited to have you
                    on board. EduLink is your one-stop student portal to manage all
                    your academic needs. Stay connected, stay informed.
                    Use the following OTP to complete your Sign Up procedures. OTP is valid for 5 minutes</p>
                <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">{{ otp }}</h2>
                <p style="font-size:0.9em;">Regards,<br />Edulink</p>
                <hr style="border:none;border-top:1px solid #eee" />
                <div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300">
                    <p>thanku!</p>
                </div>
            </div>
        </div>
        """,
        otp=otp
    )

    msg = Message('Your OTP Code', sender='ishika190205@gmail.com', recipients=[email])
    msg.html = html_body
    mail.send(msg)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data received or invalid JSON format'}), 400

        form = RegisterForm(data=data)

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

            otp = generate_otp()

            send_otp_email(email, otp)

            # Store the user in the database with confirmed=False
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(name=name, email=email, password=hashed_password, confirmed=False, otp=otp)

            db.session.add(new_user)
            db.session.commit()

            logger.info(f"User registered successfully: {email}")
            return jsonify({'message': 'User registered successfully. Please check your email for the OTP.'}), 200

        else:
            errors = form.errors
            return jsonify({'message': 'Validation failed', 'errors': errors}), 400

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error registering user: {e}")
        return jsonify({'message': 'Error registering user'}), 500

from datetime import datetime, timedelta

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        if not data or 'otp' not in data:
            return jsonify({'message': 'OTP is required in the request'}), 400
        
        otp = data['otp']

        # Check if OTP length is less than 5 digits
        if len(otp) < 5:
            return jsonify({'message': 'Enter the complete OTP'}), 400

        # Retrieve user from database
        user = User.query.filter_by(otp=otp).first()
        if not user:
            return jsonify({'message': 'User not found or Incorrect OTP'}), 404

        # Check if OTP matches
        if otp != user.otp:
            return jsonify({'message': 'Incorrect OTP'}), 400

        # Check OTP expiration (for example, 5 minutes)
        if (datetime.utcnow() - user.created_at).total_seconds() > 300:
            user.otp = None  # Clear OTP
            db.session.commit()
            return jsonify({'message': 'Time up. Kindly resend the OTP.'}), 400

        # Mark user as confirmed
        user.confirmed = True
        user.confirmed_on = datetime.utcnow()
        user.otp = None  # Clear OTP
        db.session.commit()

        return jsonify({'message': 'Email confirmed successfully'}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error verifying OTP: {e}")
        return jsonify({'message': 'Error verifying OTP', 'error': str(e)}), 500


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

        if not user.confirmed:
            return jsonify({'message': 'Email not verified. Please check your email for the OTP.'}), 403

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
        logger.debug("User logged out successfully")
        return resp

    except Exception as e:
        logger.error(f"Error during logout: {e}")
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
