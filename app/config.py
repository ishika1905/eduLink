from datetime import timedelta
class Config:
    SECRET_KEY = 'thisisasecretkey'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:Ishu2005@localhost/db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = False  # Disable CSRF for now; enable it when needed
    MONGO_URI = 'mongodb://localhost:27017/flask_logs'
    JWT_SECRET_KEY = 'jwtverysecretstring'
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_TYPE = 'Bearer'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=12)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    MAIL_SERVER = 'smtp.gmail.com'  # Replace with your SMTP server
    MAIL_PORT = 587  # Port for TLS/STARTTLS
    MAIL_USE_TLS = True  # Enable TLS/STARTTLS
    MAIL_USERNAME = 'ishika190205@gmail.com'  # Your email username
    MAIL_PASSWORD = 'xxgm rdmo odtq ywxw'  # Your email password
    SECURITY_PASSWORD_SALT = '3777b9f467ac6e374b0681aed52410d0'
    
    GOOGLE_CLIENT_ID = '664541985566-4mjnvqtn9f7r9mib52gm1u5bnh5t8o3j.apps.googleusercontent.com'
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
