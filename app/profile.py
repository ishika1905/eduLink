from flask import jsonify,request
from app.models import User  # Adjust this import based on your actual models structure
from app import app, db, token_in_database_required
from flask_jwt_extended import get_jwt_identity
@app.route('/profile', methods=['GET', 'PUT'])
@token_in_database_required
def profile():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
        
    if not user:
        return {'message': 'User not found'}, 404
    
    
    if request.method == 'GET':
        profile_data = {
            "name": user.name,
            "email": user.email,
            "profile_picture": f"{user.profile_picture}" if user.profile_picture else "/Users/angie/StudioProjects/flutter_app/profile_images/pfp.png",
            "about":"I'm a passionate and driven university student majoring in Computer Engineering at University of Wisconsin-Madison. My academic journey is fueled by a curiosity for mobile app development, where I aim to blend theoretical knowledge with practical experience. Outside the classroom, I engage in swimming and enjoy exploring nature. Im committed to continuous learning and making a positive impact in my community.",
            "courses": ["ECAS 130C Introduction to Computer-Assisted Surgery", "EDCN 532C Digital Communication Networks", "EEMI 432C Microelectronics"]  
        }       
        return jsonify(profile_data), 200
    
    elif request.method == 'PUT':
        try:
            data = request.get_json()
            if not data:
                print("No data provided")
                return jsonify({'message': 'Invalid request: No data provided'}), 400
            
            print("Received data:", data)  # Debugging line
            
            profile_picture = data.get('profile_picture')
            if not profile_picture:
                print("No profile_picture provided")
                return jsonify({'message': 'Invalid request: No profile_picture provided'}), 400
            
            print("Profile picture:", profile_picture)  # Debugging line
            
            # Ensure the selected picture is one of the allowed options
            allowed_pictures = ["/Users/angie/StudioProjects/flutter_app/profile_images/bird.png", "/Users/angie/StudioProjects/flutter_app/profile_images/bunny.png", "/Users/angie/StudioProjects/flutter_app/profile_images/cat.png", "/Users/angie/StudioProjects/flutter_app/profile_images/Dog.png"]
            if profile_picture not in allowed_pictures:
                print("Invalid profile picture selection")
                return jsonify({'message': 'Invalid profile picture selection'}), 400
            
            user.profile_picture = profile_picture
            db.session.commit()
            
            print("Profile picture updated successfully")  # Debugging line
            return jsonify({'message': 'Profile picture updated successfully'}), 200
        
        except Exception as e:
            print("Error occurred:", str(e))
            return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

    # If the request method is not GET or PUT, return a 405 Method Not Allowed
    return jsonify({'message': 'Method Not Allowed'}), 405

