from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'

db = SQLAlchemy(app)

# Track login attempts
login_attempts = {}

# User table design
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    profile_pic = db.Column(db.String(200))

# Create database
with app.app_context():
    db.create_all()

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        file = request.files['profile_pic']

        hashed_password = generate_password_hash(password)

        # Save the photo
        filename = secure_filename(file.filename)
        profile_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Create the folder if it doesn't exist
        folder_path = os.path.dirname(profile_path)
        os.makedirs(folder_path, exist_ok=True)

        file.save(profile_path)

        # Store user in database
        new_user = User(username=username, email=email, password=hashed_password, profile_pic=profile_path)
        db.session.add(new_user)
        db.session.commit()

        flash('Registered successfully! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route with 3 attempts limit
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Stop login if 3 wrong attempts
        if login_attempts.get(username, 0) >= 3:
            flash('⛔ Time Finished. Too many wrong login attempts.')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            login_attempts[username] = 0  # Reset after successful login
            flash('✅ Login successful!')
            return redirect(url_for('index'))
        else:
            login_attempts[username] = login_attempts.get(username, 0) + 1
            remaining = 3 - login_attempts[username]
            if remaining > 0:
                flash(f'❌ Wrong credentials. {remaining} attempt(s) left.')
            else:
                flash('⛔ Time Finished. Too many wrong login attempts.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Home page after login
@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    else:
        flash('Please login first.')
        return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)