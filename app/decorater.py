from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from flask_login import login_user
from app.models import User

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
