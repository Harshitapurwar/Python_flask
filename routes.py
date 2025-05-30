
import os
from flask import render_template, request, redirect, url_for, flash, session,jsonify
from werkzeug.utils import secure_filename
from app import app, db
from models import User, UserProfile, WorkerProfile,ChatMessage
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_socketio import SocketIO, join_room, leave_room, send,emit
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.linkedin import make_linkedin_blueprint, linkedin
from flask_sqlalchemy import SQLAlchemy
from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
from flask_mail import Mail, Message
from forms import RequestResetForm, ResetPasswordForm
from forms import RequestResetForm,ResetPasswordForm
from flask_login import login_user, current_user, logout_user, login_required,current_user, UserMixin
from app import app, db, mail, login_manager,bcrypt


# Configure logging
logging.basicConfig(level=logging.INFO)

# mail=Mail(app)


messages=[]

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif','avif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

socketio = SocketIO(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # for localhost only

# db = SQLAlchemy(app)

# Login
# login_manager = LoginManager(app)
# login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(256), unique=True)
#     provider = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Google OAuth
google_bp = make_google_blueprint(
    client_id='GOOGLE_CLIENT_ID',
    client_secret='GOOGLE_CLIENT_SECRET',
    scope=['profile', 'email'],
    redirect_to='google_login'
)
app.register_blueprint(google_bp, url_prefix="/login")

# GitHub OAuth
github_bp = make_github_blueprint(
    client_id='GITHUB_CLIENT_ID',
    client_secret='GITHUB_CLIENT_SECRET',
    redirect_to='github_login'
)
app.register_blueprint(github_bp, url_prefix="/login")

# LinkedIn OAuth
linkedin_bp = make_linkedin_blueprint(
    client_id='LINKEDIN_CLIENT_ID',
    client_secret='LINKEDIN_CLIENT_SECRET',
    redirect_to='linkedin_login',
    scope=["r_liteprofile", "r_emailaddress"]
)
app.register_blueprint(linkedin_bp, url_prefix="/login")

# google_bp = make_google_blueprint(client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, redirect_to='google_authorized')
# linkedin_bp = make_linkedin_blueprint(client_id=LINKEDIN_CLIENT_ID, client_secret=LINKEDIN_CLIENT_SECRET, redirect_to='linkedin_authorized')
# github_bp = make_github_blueprint(client_id=GITHUB_CLIENT_ID, client_secret=GITHUB_CLIENT_SECRET, redirect_to='github_authorized')

# app.register_blueprint(google_bp, url_prefix='/google_login')
# app.register_blueprint(linkedin_bp, url_prefix='/linkedin_login')
# app.register_blueprint(github_bp, url_prefix='/github_login')

@app.route('/')
def home():
    if 'user_id' in session:  
        return redirect(url_for('dashboard'))  
    return redirect(url_for('login'))

from flask_mail import Message
from app import mail
from flask import current_app, url_for

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def send_reset_email(user, token):
    msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    mail.send(msg)
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.get_reset_token()
            send_reset_email(user, token)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email does not exist.', 'warning')
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route('/reset_token/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    user_id = User.verify_reset_token(token)
    if user_id is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    
    user = User.query.get(user_id)
    if user is None:
        flash('No user found with that ID.', 'warning')
        return redirect(url_for('reset_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password_hash = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_token.html', title='Reset Password', form=form)



@app.route('/worker_registration', methods=['GET', 'POST'])
def worker_registration():
    if request.method == 'POST':
        try:
            # Worker information
            fname = request.form['fname']
            lname = request.form['lname']
            phone = request.form['phone']
            street = request.form['street']
            city = request.form['city']
            postal_code = request.form['postal_code']
            state = request.form['state']
            country = request.form['country']
            service_type = request.form['service_type']
            avatar = None

            if 'avatar' in request.files:
                file = request.files['avatar']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    avatar = filename

            # Create WorkerProfile instance
            new_worker = WorkerProfile(
                fname=fname, lname=lname,
                phone=phone, street=street, city=city,
                postal_code=postal_code, state=state,
                country=country, avatar=avatar,
                service_type=service_type
            )
            db.session.add(new_worker)
            db.session.commit()

            flash('Worker profile saved successfully!', 'success')
            return redirect(url_for('landing', service_type='all'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error saving worker profile: {e}")
            flash('Error saving worker profile', 'danger')
            return redirect(url_for('worker_registration.html'))
      


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(name=name, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user) 
            flash('User successfully registered', 'success')
            session['user_id'] = new_user.id  
            return redirect(url_for('index')) 
        except Exception as e:
            db.session.rollback()  
            logging.error(f"Error creating user: {e}")
            flash('User already exists or other error', 'danger')

    return render_template('signup.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        print("User is already authenticated, redirecting to landing")
        return redirect(url_for('landing'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        print(f"Email: {email}, Password: {password}")

        user = User.query.filter_by(email=email).first()
        if user:
            print("User found")

        if user and check_password_hash(user.password, password):
            login_user(user, remember=request.form.get('remember_me'))
            flash('Logged in successfully!', 'success')
            return redirect(url_for('landing'))  # ✅ Go to landing after login
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')

    return render_template('login.html')





@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    try:
        logout_user()
        session.clear()  
        db.session.commit()
        flash('You have been logged out successfully!', 'success')
        return redirect(url_for('login'))  
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Exception on /logout: {str(e)}")
        flash('An error occurred during logout. Please try again.', 'danger')
        return redirect(url_for('dashboard'))  
    

@app.route("/login/google")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        email = resp.json()["email"]
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, provider="google")
            db.session.add(user)
            db.session.commit()
        login_user(user)
        flash("Logged in with Google", "success")
        return redirect(url_for("dashboard"))
    flash("Google login failed", "danger")
    return redirect(url_for("home"))

@app.route("/login/github")
def github_login():
    if not github.authorized:
        return redirect(url_for("github.login"))

    resp = github.get("/user")
    if resp.ok:
        email = resp.json().get("email") or f"{resp.json()['id']}@github.com"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, provider="github")
            db.session.add(user)
            db.session.commit()
        login_user(user)
        flash("Logged in with GitHub", "success")
        return redirect(url_for("dashboard"))
    flash("GitHub login failed", "danger")
    return redirect(url_for("home"))

@app.route("/login/linkedin")
def linkedin_login():
    if not linkedin.authorized:
        return redirect(url_for("linkedin.login"))

    email_resp = linkedin.get("v2/emailAddress?q=members&projection=(elements*(handle~))")
    profile_resp = linkedin.get("v2/me")

    if email_resp.ok and profile_resp.ok:
        email = email_resp.json()["elements"][0]["handle~"]["emailAddress"]
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, provider="linkedin")
            db.session.add(user)
            db.session.commit()
        login_user(user)
        flash("Logged in with LinkedIn", "success")
        return redirect(url_for("dashboard"))
    flash("LinkedIn login failed", "danger")
    return redirect(url_for("home"))





@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to edit your profile', 'danger')
        return redirect(url_for('login'))

    profile = UserProfile.query.filter_by(user_id=user_id).first()

    if request.method == 'POST':
        try:
            # Update profile information
            profile.fname = request.form['fname']
            profile.lname = request.form['lname']
            profile.phone = request.form['phone']
            profile.street = request.form['street']
            profile.city = request.form['city']
            profile.postal_code = request.form['postal_code']
            profile.state = request.form['state']
            profile.country = request.form['country']

            # Check if the post request has the file part
            if 'avatar' in request.files:
                file = request.files['avatar']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    profile.avatar = filename

            db.session.commit()

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            logging.error(f"Error updating profile: {e}")
            flash('Error updating profile', 'danger')
            return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', profile=profile)


@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')  
    if user_id:
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        return render_template('dashboard.html', profile=profile)
    else:
        flash('User not logged in', 'danger')
        return redirect(url_for('login'))  


# Profile route
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view or edit your profile', 'danger')
        return redirect(url_for('login'))

    profile = UserProfile.query.filter_by(user_id=user_id).first()

    if request.method == 'POST':
        try:
            fname = request.form['fname']
            lname = request.form['lname']
            phone = request.form['phone']
            street = request.form['street']
            city = request.form['city']
            postal_code = request.form['postal_code']
            state = request.form['state']
            country = request.form['country']
            avatar = None

            if 'avatar' in request.files:
                file = request.files['avatar']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    avatar = filename

            if profile:
                profile.fname = fname
                profile.lname = lname
                profile.phone = phone
                profile.street = street
                profile.city = city
                profile.postal_code = postal_code
                profile.state = state
                profile.country = country
                if avatar:
                    profile.avatar = avatar
            else:
                new_profile = UserProfile(
                    user_id=user_id,
                    fname=fname, lname=lname,
                    phone=phone, street=street, city=city,
                    postal_code=postal_code, state=state,
                    country=country, avatar=avatar
                )
                db.session.add(new_profile)

            db.session.commit()
            flash('Profile saved successfully!', 'success')
            return redirect(url_for('landing'))  
        except Exception as e:
            db.session.rollback()
            flash('Error saving profile', 'danger')
            return redirect(url_for('profile'))

    return render_template('profile.html', profile=profile)
    
@app.route('/portal')
def portal():
    user_id = session.get('user_id')
    if not user_id:
        flash('User not logged in', 'danger')
        return redirect(url_for('login'))

    profile = UserProfile.query.filter_by(user_id=user_id).first()
    if profile and profile.postal_code:
        workers = WorkerProfile.query.filter_by(postal_code=profile.postal_code).all()
    else:
        workers = []

    return render_template('portal.html', workers=workers)

@app.route('/myprofile')
def myprofile():
    user_id = session.get('user_id')
    if not user_id:
        flash('User not logged in', 'danger')
        return redirect(url_for('login'))

    profile = UserProfile.query.filter_by(user_id=user_id).first()
    if profile:
        app.logger.info(f"Profile found: {profile.fname} {profile.lname}")
    else:
        app.logger.info("No profile found for user")

    return render_template('myprofile.html', profile=profile)





@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    username = data.get('username')
    message = data.get('message')
    if username and message:
        messages.append({'username': username, 'message': message})
        return jsonify({'success': True}), 200
    else:
        return jsonify({'success': False, 'error': 'Invalid username or message'}), 400

@app.route('/services')
@login_required
def services():
    return render_template('services.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')
@app.route('/chats')
def chats():
    return render_template('chats.html')

@app.route('/footer')
def footer():
    return render_template('footer.html')


# @app.route('/index')
# @login_required
# def index():

#     session['logged_in'] = False  
#     profile = None  
#     return render_template('landing.html',  user=current_user)
# @app.route('/index')
# def index():
#     return render_template('index.html')
@app.route('/index')
def index():
    return render_template('index.html')   



@app.route('/worker_card/<service_type>', methods=['GET', 'POST'])
def worker_card(service_type):
    if request.method == 'POST':
        user_postal_code = request.form.get('postal_code')
        print(f"Postal code from POST form: {user_postal_code}")  # Debugging
        if user_postal_code:
            session['user_postal_code'] = user_postal_code
    else:
        user_postal_code = session.get('user_postal_code')
        print(f"Postal code from session: {user_postal_code}")

    if user_postal_code:
        workers = WorkerProfile.query.filter_by(postal_code=user_postal_code, service_type=service_type).all()
        print(f"Filtered workers: {workers}")  # Debugging
    else:
        workers = []
        print("No postal code provided, no workers to show.")

    return render_template('worker_card.html', service_type=service_type, workers=workers, user_postal_code=user_postal_code)


@app.route('/landing')
@login_required
def landing():
    profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    if profile and profile.postal_code:
        workers = WorkerProfile.query.filter_by(postal_code=profile.postal_code).all()
    else:
        workers = []

    # Group workers by service type
    workers_by_type = {}
    for worker in workers:
        service_type = worker.service_type
        if service_type not in workers_by_type:
            workers_by_type[service_type] = []
        if len(workers_by_type[service_type]) < 3:
            workers_by_type[service_type].append(worker)

    return render_template('landing.html', profile=profile, workers_by_type=workers_by_type)



@app.route('/get_chat_messages')
def get_chat_messages():
    return jsonify(messages)


if __name__ == '__main__':
    db.create_all()
    socketio.run(app, debug=True)
