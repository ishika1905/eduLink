# EduLink

EduLink is an online learning platform developed with Flutter, RESTful APIs using Flask, and MySQL connectivity. The app aims to bring educational content directly to your mobile device. With EduLink, you can watch lectures and access a wide range of educational resources. Whether you’re a student seeking to learn new subjects or a professional looking to enhance your skills, EduLink provides a convenient and interactive way to stay connected with your learning journey anytime, anywhere.

(This project serves as a starting point for applications integrating Flask-based backends.)

---

## Features

- **User Authentication:** Secure OTP-based email verification and Google sign-in.
- **Password Management:** Forgot and reset password options for users.
- **Lecture Playback:** YouTube-integrated video streaming for seamless learning.
- **Personalization:** Customize your profile, track achievements, and manage completed courses.
- **Profile Pictures:** Select an avatar or upload a profile picture from your gallery.
- **Course Management:** Favorite/unfavorite courses of your liking.
- **Search Functionality:** Real-time search bar for finding courses and content.
- **Course Listing:** Efficient pagination for smooth browsing of available courses.

---

## Tech Stack

- **Frontend:** Flutter (Dart) for a responsive and interactive user interface.
- **Backend:** Flask for robust RESTful API implementation.
- **Database:** MySQL for structured and reliable data management and MongoDB for the URL Logs.

---

## Installation and Setup

1. **Clone the Repository:**
   - Backend:
     
     git clone https://github.com/ishika1905/eduLink.git
     cd eduLink
     
   - Frontend:
     
     git clone https://github.com/ishika1905/edulink-flutter.git
     cd edulink-flutter
     

2. **Backend Setup:**
   - Install Python dependencies:
     
     pip install -r requirements.txt
     
   - Configure the MySQL database:
     - Set up the schema and update the database connection in the Flask configuration file.
   - Run the Flask server:
     
     python app.py

     
3. **Frontend Setup:**
   - Ensure Flutter is installed on your machine.
   - Navigate to the frontend directory and run:
     
     flutter pub get
     flutter run
     

---

## Usage

1. Launch the application on a mobile emulator or device.
2. Register or log in as a student.
3. Explore features such as:
   - Watching lectures.
   - Managing your profile and achievements.
   - Browsing and searching for courses.

---

Here is flutter code : https://github.com/ishika1905/edulink-flutter for reference!
