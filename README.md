# 🎥 Media Dashboard

Media Dashboard is a web-based application that allows users to upload and play videos, play YouTube videos, and convert speech into text using voice recording.

The application also provides user registration and login functionality.

## 🚀 Features

* 🔐 User Registration and Login
* 🖼️ Profile Picture Upload
* 🎥 Upload and Play Video
* ▶️ Play YouTube Videos
* 🎙️ Speech Recognition
* 📝 Audio Transcription
* 🔒 Login Attempt Limitation
* 🚪 Logout

## 🛠️ Technologies Used

* Python
* Flask
* Flask-SQLAlchemy
* SQLite
* HTML5
* CSS3
* JavaScript
* Web Speech API
* YouTube Embed

## 🔄 How It Works

```text
User
 ↓
Flask Web Application
 ↓
Login / Register
 ↓
Media Dashboard
 ├── Upload Video
 ├── Play YouTube Video
 └── Speech Recognition
```

## 🎙️ Speech Recognition

The project uses the browser's **Web Speech API** to convert the user's speech into text.

```text
User speaks
    ↓
Speech Recognition
    ↓
Convert Speech to Text
    ↓
Display Transcription
```

The application uses the browser's Speech Recognition API and works best in browsers that support it, such as Google Chrome.

## 🔐 User Authentication

Users can:

* Register an account
* Upload a profile picture
* Login using username and password
* Logout from the application

Passwords are stored using password hashing instead of plain text.

The application also limits incorrect login attempts to **3 attempts**.

## 🎥 Video Features

Users can select a local video file and play it directly in the browser.

The application also allows users to enter a YouTube URL and play the video using a YouTube embedded player.

## 🗄️ Database

The project uses **SQLite** with **Flask-SQLAlchemy**.

The user table stores:

```text
id
username
email
password
profile_pic
```

## 📂 Project Structure

```text
Media-Dashboard/
│
├── speech_project/
│   ├── app.py
│   │
│   ├── static/
│   │   └── profile_pics/
│   │
│   ├── templates/
│   │   ├── index.html
│   │   ├── login.html
│   │   └── register.html
│   │
│   ├── instance/
│   │   └── users.db
│   │
│   └── user.db
│
└── README.md
```

## ⚙️ How to Run

### 1. Clone the repository

```bash
git clone https://github.com/sharumathi755/media_dashboard_project1.git
```

> Replace the repository name with your actual GitHub repository name if it is different.

### 2. Open the project

```bash
cd media_dashboard_project1
```

### 3. Install required packages

```bash
pip install flask flask-sqlalchemy werkzeug
```

### 4. Run the application

```bash
python speech_project/app.py
```

### 5. Open in browser

```text
http://127.0.0.1:5000
```

## 🎯 Learning Outcomes

Through this project, I learned:

* Python Flask
* Flask-SQLAlchemy
* SQLite database
* User authentication
* Password hashing
* File upload handling
* HTML, CSS and JavaScript
* JavaScript Web Speech API
* Video handling
* YouTube embedding
* Session management

## 🔮 Future Improvements

* 🎙️ Support more languages for speech recognition
* 📧 Save and export transcriptions
* 👤 User profile management
* ☁️ Cloud storage for uploaded videos
* 📱 Improve mobile responsiveness
* 🔐 Add stronger authentication and security

## 👩‍💻 Author

**Sharumathi G**

GitHub: https://github.com/sharumathi755

---

⭐ Developed as a learning project to explore Flask, databases, media handling and speech recognition.
