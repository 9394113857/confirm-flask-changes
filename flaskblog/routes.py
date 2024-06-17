import os
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import date, datetime, timedelta
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, jsonify, make_response
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, RequestResetForm, ResetPasswordForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import jwt
from functools import wraps

# Set up logger configuration
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
current_year = date.today().strftime('%Y')
current_month = date.today().strftime('%m')
year_month_dir = os.path.join(logs_dir, current_year, current_month)
os.makedirs(year_month_dir, exist_ok=True)
log_file = os.path.join(year_month_dir, f'{date.today()}.log')
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s'))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

def generate_access_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def generate_refresh_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'x-access-token' not in request.cookies:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            access_token = request.cookies.get('x-access-token')
            jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated_function

def send_verification_email(user):
    token = user.get_verification_token()
    msg = Message('Email Verification', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not create an account, please ignore this email.
'''
    mail.send(msg)

@app.route("/")
@app.route("/home")
def home():
    try:
        page = request.args.get('page', 1, type=int)
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
        return render_template('home.html', posts=posts)
    except Exception as e:
        logger.error(f"Error in home route: {str(e)}")
        abort(500)

@app.route("/about")
def about():
    return render_template('about.html', title='About')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            send_verification_email(user)
            flash('An email has been sent with instructions to verify your email.', 'info')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in register route: {str(e)}")
            flash('An error occurred. Please try again later.', 'danger')
            db.session.rollback()
    return render_template('register.html', title='Register', form=form)

@app.route("/verify_email/<token>", methods=['GET'])
def verify_email(token):
    user = User.verify_verification_token(token)
    if user:
        user.verified = True
        db.session.commit()
        flash('Your email has been verified. You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('The verification link is invalid or expired.', 'danger')
        return redirect(url_for('home'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                if user.verified:
                    login_user(user, remember=form.remember.data)
                    access_token = generate_access_token(identity=user.id)
                    response = make_response(redirect(url_for('home')))
                    response.set_cookie('x-access-token', access_token, httponly=True)
                    next_page = request.args.get('next')
                    return response if not next_page else redirect(next_page)
                else:
                    flash('Your email is not verified. Please check your email.', 'warning')
                    return redirect(url_for('login'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        except Exception as e:
            logger.error(f"Error in login route: {str(e)}")
            flash('An error occurred. Please try again later.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('x-access-token')
    return response

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        try:
            if form.picture.data:
                picture_file = save_picture(form.picture.data)
                current_user.image_file = picture_file
            current_user.username = form.username.data
            current_user.email = form.email.data
            db.session.commit()
            flash('Your account has been updated!', 'success')
            return redirect(url_for('account'))
        except Exception as e:
            logger.error(f"Error in account route: {str(e)}")
            flash('An error occurred. Please try again later.', 'danger')
            db.session.rollback()
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        try:
            post = Post(title=form.title.data, content=form.content.data, author=current_user)
            db.session.add(post)
            db.session.commit()
            flash('Your post has been created!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            logger.error(f"Error in new_post route: {str(e)}")
            flash('An error occurred. Please try again later.', 'danger')
            db.session.rollback()
    return render_template('create_post.html', title='New Post', form=form, legend='New Post')

@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        try:
            post.title = form.title.data
            post.content = form.content.data
            db.session.commit()
            flash('Your post has been updated!', 'success')
            return redirect(url_for('post', post_id=post.id))
        except Exception as e:
            logger.error(f"Error in update_post route: {str(e)}")
            flash('An error occurred. Please try again later.', 'danger')
            db.session.rollback()
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Update Post', form=form, legend='Update Post')

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    try:
        db.session.delete(post)
        db.session.commit()
        flash('Your post has been deleted!', 'success')
    except Exception as e:
        logger.error(f"Error in delete_post route: {str(e)}")
        flash('An error occurred. Please try again later.', 'danger')
        db.session.rollback()
    return redirect(url_for('home'))

@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)
    flash('An email has been sent with instructions to reset your password.', 'info')
    return redirect(url_for('login'))

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

# Error handling for 403 Forbidden error
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# Error handling for 404 Not Found error
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

# Error handling for 500 Internal Server Error
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Rollback any database changes due to the error
    return render_template('errors/500.html'), 500    
