# app.py

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong, random key

# Replace the following dictionary with a secure database solution in a real-world application
users = {'user1': generate_password_hash('password1'), 'user2': generate_password_hash('password2')}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        if username in users:
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='sha256')
        users[username] = hashed_password

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('options'))
        else:
            flash('Login failed. Check your username and password.', 'error')

    return render_template('login.html')

@app.route('/options')
def options():
    if 'username' in session:
        return render_template('inside.html', username=session['username'])
    else:
        flash('You are not logged in. Please log in.', 'error')
        return redirect(url_for('login'))
        
@app.route("/f1")
def download_f1():
    with open('./safe/file1.txt') as f:
        lines = f.readlines()
    return (lines)

@app.route("/f2")
def download_f2():
    with open('./safe/file1.txt') as f:
        lines = f.readlines()
    return (lines)

@app.route("/f3")
def download_f3():
    with open('./safe/file1.txt') as f:
        lines = f.readlines()
    return (lines)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)