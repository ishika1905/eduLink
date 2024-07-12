
from flask import jsonify
from app import app,db
from app.auth import register, login, logout,google_auth,set_password,get_access_token
from app.tabs import get_courses, search_courses,mark_favorite, get_favorite_courses, get_lectures,remove_favorite
from app.auth import confirm_email
from app.profile import profile

# Authentication routes
app.add_url_rule('/register', 'register', register, methods=['POST'])
app.add_url_rule('/login', 'login', login, methods=['POST'])
app.add_url_rule('/logout', 'logout', logout, methods=['POST'])
app.add_url_rule('/google_auth','google_auth',google_auth ,methods=['POST'])
app.add_url_rule('/set_password','set_password',set_password, methods=['POST'])
app.add_url_rule('/get_access_token','get_access_token',get_access_token, methods=['GET'])
# Course and Lecture routes
app.add_url_rule('/home_page', 'get_courses', get_courses, methods=['GET'])
app.add_url_rule('/search', 'search_courses', search_courses, methods=['GET'])
app.add_url_rule('/add_fav', 'mark_favorite', mark_favorite, methods=['PUT'])
app.add_url_rule('/fav_courses', 'get_favorite_courses', get_favorite_courses, methods=['GET'])
app.add_url_rule('/remove_fav', 'remove_favorite',remove_favorite,methods=['DELETE'])
app.add_url_rule('/lectures', 'get_lectures', get_lectures, methods=['GET'])
app.add_url_rule('/profile', 'profile', profile, methods=['GET','PUT'])
# Confirmation route
app.add_url_rule('/confirm/<token>', 'confirm_email', confirm_email, methods=['GET'])