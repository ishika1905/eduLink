from flask import jsonify, request
from app import app, db
from app.models import Course, Lecture, FavoriteCourse
from flask_login import current_user
from app.decorater import token_in_database_required
from loguru import logger

# Course functions
@token_in_database_required
def get_courses():
    try:
        # Get page and per_page parameters from the query string, default to 1 and 10 respectively
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # Ensure page and per_page have valid values
        if page < 1 or per_page < 1:
            return jsonify({'message': 'Invalid page or per_page value'}), 400

        # Paginate the courses
        courses = Course.query.paginate(page=page, per_page=per_page)
        favorite_course_ids = {fav.course_id for fav in FavoriteCourse.query.filter_by(user_email=current_user.email).all()}
        course_list = []

        for course in courses.items:
            course_data = {
                'course_id': course.course_id,
                'course_name': course.course_name,
                'course_details': course.course_details,
                'duration': course.duration,
                'is_favorite': course.course_id in favorite_course_ids
            }
            course_list.append(course_data)

        pagination_data = {
            'total_pages': courses.pages,
            'current_page': courses.page,
            'has_next': courses.has_next,
            'has_prev': courses.has_prev
        }

        logger.info("Courses fetched successfully")
        return jsonify({'courses': course_list, 'pagination': pagination_data}), 200

    except Exception as e:
        logger.error(f"Error fetching courses: {e}")
        return jsonify({'message': 'Internal server error'}), 500


@token_in_database_required
def search_courses():
    try:
        query = request.args.get('query')

        if not query:
            return jsonify({'message': 'course is required'}), 400

        # Perform search by course_id or course_name
        courses = Course.query.filter(
            (Course.course_id.ilike(f'%{query}%')) |
            (Course.course_name.ilike(f'%{query}%'))
        ).all()

        if not courses:
            return jsonify({'message': 'No courses found matching the query'}), 404
        favorite_course_ids = {fav.course_id for fav in FavoriteCourse.query.filter_by(user_email=current_user.email).all()}
        course_list = []

        for course in courses:
            course_data = {
                'course_id': course.course_id,
                'course_name': course.course_name,
                'course_details': course.course_details,
                'duration': course.duration,
                'is_favorite': course.course_id in favorite_course_ids
            }
            course_list.append(course_data)

        logger.info("Courses searched successfully")
        return jsonify(course_list), 200

    except Exception as e:
        logger.error(f"Error searching courses: {e}")
        return jsonify({'message': 'Internal server error'}), 500    


@token_in_database_required
def mark_favorite():
    if current_user.is_anonymous:
        return jsonify({'error': 'User not authenticated'}), 401

    data = request.get_json()
    fav_id = data.get('fav_id')

    if fav_id is None:
        return jsonify({'error': 'No course ID provided'}), 400

    course = Course.query.get(fav_id)
    if not course:
        return jsonify({'error': 'Course not found'}), 404

    favorite_course = FavoriteCourse.query.filter_by(user_email=current_user.email, course_id=fav_id).first()
    if not favorite_course:
        favorite_course = FavoriteCourse(user_email=current_user.email, course_id=fav_id)
        db.session.add(favorite_course)
        db.session.commit()

    logger.info(f"Course {fav_id} marked as favorite for user {current_user.email}")
    return jsonify({'message': 'Course marked as favorite','favorite':True}), 200


@token_in_database_required
def get_favorite_courses():
    if current_user.is_anonymous:
        return jsonify({'error': 'User not authenticated'}), 401

    try:
        favorite_courses = FavoriteCourse.query.filter_by(user_email=current_user.email).all()

        if not favorite_courses:
            return jsonify({'message': 'No favorite courses selected lol'}), 200

        favorite_course_list = [
            {
                'course_id': fav.course.course_id,
                'course_name': fav.course.course_name,
                'course_details': fav.course.course_details,
                'duration': fav.course.duration
            } for fav in favorite_courses
        ]

        logger.info("Favorite courses fetched successfully")
        return jsonify(favorite_course_list), 200

    except Exception as e:
        logger.error(f"Error fetching favorite courses: {e}")
        return jsonify({'message': 'Internal server error'}), 500


@token_in_database_required
def remove_favorite():
    if current_user.is_anonymous:
        return jsonify({'error': 'User not authenticated'}), 401

    data = request.get_json()
    fav_id = data.get('fav_id')

    if fav_id is None:
        return jsonify({'error': 'No course ID provided'}), 400

    favorite_course = FavoriteCourse.query.filter_by(user_email=current_user.email, course_id=fav_id).first()
    if not favorite_course:
        return jsonify({'error': 'Favorite course not found'}), 404

    db.session.delete(favorite_course)
    db.session.commit()

    logger.info(f"Course {fav_id} removed from favorites for user {current_user.email}")
    return jsonify({'message': 'Course removed from favorites', 'favorite': False}), 200


# Lecture functions
@token_in_database_required
def get_lectures():
    try:
        lectures = Lecture.query.all()
        lecture_list = [{
            'course_id': lecture.course_id,
            'title': lecture.title,
            'youtube_url': lecture.youtube_url,
        } for lecture in lectures]

        logger.info("Lectures fetched successfully")
        return jsonify(lecture_list), 200

    except Exception as e:
        logger.error(f"Error fetching lectures: {e}")
        return jsonify({'message': 'Internal server error'}), 500
