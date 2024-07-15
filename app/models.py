from . import db
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()

from app import app
from . import db  # Assuming your db instance is imported from your application package

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    email = db.Column(db.String(255), primary_key=True)  # Primary key
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    confirm_password = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.String(1000))
    confirmed = db.Column(db.Boolean, default=False)  # Add confirmed attribute
    confirmed_on = db.Column(db.DateTime)  # Optional: Add confirmed_on timestamp
    profile_picture = db.Column(db.String(150), nullable=True, default='/Users/angie/StudioProjects/flutter_app/profile_images/pfp.png')
    favorite_courses = db.relationship('FavoriteCourse', back_populates='user')

    def get_id(self):
        return self.email

    def __repr__(self):
        return f'<User {self.email} - {self.name}>'
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    
class Course(db.Model):
    __tablename__ = 'course'
    course_id = db.Column(db.String(50), primary_key=True)
    course_name = db.Column(db.String(255), nullable=False)
    course_details = db.Column(db.String(1000))
    duration = db.Column(db.String(50))
    favorite = db.Column(db.Boolean, default=False)
    fav_id=db.Column(db.String(50))
    favorite_users = db.relationship('FavoriteCourse', back_populates='course')
    def __repr__(self):
        return f'<Course {self.course_name}>'
    
    
class FavoriteCourse(db.Model):
    __tablename__ = 'favorite_courses'
    user_email = db.Column(db.String(255), db.ForeignKey('user.email'), primary_key=True, nullable=False)
    course_id = db.Column(db.String(50), db.ForeignKey('course.course_id'), primary_key=True, nullable=False)
    user = db.relationship('User', back_populates='favorite_courses')
    course = db.relationship('Course', back_populates='favorite_users')
  

class Lecture(db.Model):
    __tablename__ = 'lectures'
    course_id = db.Column(db.String(255), db.ForeignKey('course.course_id'), primary_key=True, nullable=False)
    title = db.Column(db.String(255), primary_key=True, nullable=False)
    youtube_url = db.Column(db.String(255), nullable=False)
    
    def __repr__(self):
        return f'<Lecture {self.title}>'
    
