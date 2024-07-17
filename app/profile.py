
from flask import jsonify, request
from app.models import User  # Adjust this import based on your actual models structure
from app import app, db
from app.decorater import token_in_database_required
from flask_jwt_extended import get_jwt_identity
from loguru import logger
from pymongo import MongoClient

# client = MongoClient('mongodb://localhost:27017/')
# db_mongo = client['flask_logs']
# log_collection = db_mongo['logs']

@app.route('/profile', methods=['GET', 'PUT'])
@token_in_database_required
def profile():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user:
        logger.error(f"User {current_user_email} not found")
        return {'message': 'User not found'}, 404
    
    if request.method == 'GET':
        #user_logs = list(log_collection.find({'message': {'$regex': current_user_email}}, {'_id': 0}))
        
        #logger.debug(f"Fetched logs for user {current_user_email}: {user_logs}")
         
        profile_data = {
            "name": user.name,
            "email": user.email,
            "profile_picture": user.profile_picture if user.profile_picture else "/Users/angie/StudioProjects/flutter_app/profile_images/pfp.png",
            "about": "I'm a passionate and driven university student majoring in Computer Engineering at University of Wisconsin-Madison. My academic journey is fueled by a curiosity for mobile app development, where I aim to blend theoretical knowledge with practical experience. Outside the classroom, I engage in swimming and enjoy exploring nature. I'm committed to continuous learning and making a positive impact in my community.",
            "courses": ["ECAS 130C Introduction to Computer-Assisted Surgery", "EDCN 532C Digital Communication Networks", "EEMI 432C Microelectronics"]
           # "logs": user_logs 
        }
        logger.info(f"Profile data fetched for user {current_user_email}")
        return jsonify(profile_data), 200
    
    elif request.method == 'PUT':
        try:
            data = request.get_json()
            if not data:
                logger.warning("No data provided for profile update")
                return jsonify({'message': 'Invalid request: No data provided'}), 400

            logger.info(f"Received profile update request: {data}")
            profile_picture = data.get('profile_picture')
            if not profile_picture:
                logger.warning("No profile_picture provided for profile update")
                return jsonify({'message': 'Invalid request: No profile_picture provided'}), 400

            # Update user profile picture
            user.profile_picture = profile_picture
            db.session.commit()
            logger.info(f"Profile picture updated successfully for user {current_user_email}")
            return jsonify({'message': 'Profile picture updated successfully'}), 200

        except Exception as e:
            logger.error(f"Error occurred while updating profile picture: {e}")
            return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

    # If the request method is not GET or PUT, return a 405 Method Not Allowed
    logger.warning("Invalid method used for profile endpoint")
    return jsonify({'message': 'Method Not Allowed'}), 405
