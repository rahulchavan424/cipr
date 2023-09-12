from flask import render_template, url_for, redirect, flash, request, session, jsonify
from app import app, db
from forms import IPCreateForm, IPSearchForm, RegistrationForm, LoginForm, UserProfileForm
from models import User, IP
from auth import require_auth_token, require_role
from roles import UserRole
import os
from werkzeug.utils import secure_filename
from sqlalchemy import desc

# file upload extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/get_subcategories', methods=['GET'])
@require_auth_token
def get_subcategories():
    category = request.args.get('category')
    subcategory_choices = []

    if category:
        # fetch subcategories based on the selected category
        subcategory_choices = [row.subcategory for row in IP.query.filter_by(category=category).distinct().all()]

    return jsonify(subcategory_choices)

@app.route('/', methods=['GET', 'POST'])
@require_auth_token
def home():
    form = IPSearchForm()
    search_results = []
    auth_token = session.get('auth_token')

    if auth_token:
        user = User.query.filter_by(auth_token=auth_token).first()

        if user:
            category_choices = [(row.category, row.category) for row in db.session.query(IP.category).distinct()]
            category_choices.insert(0, ('', 'IP Category'))
            form.category.choices = category_choices

            query = IP.query.order_by(desc(IP.id)) 

            category = form.category.data
            if category and category != '':
                query = query.filter_by(category=category)

                subcategory = form.subcategory.data
                if subcategory and subcategory != '':
                    query = query.filter_by(subcategory=subcategory)

            search_query = form.search_query.data

            if form.is_submitted() and search_query:
                query = query.filter(IP.short_description.ilike(f'%{search_query}%'))

            # limit query results
            search_results = query.limit(5).all()
            
            return render_template('home.html', form=form, ips=search_results)

    flash('You need to be logged in to access this page.', 'info')
    return redirect(url_for('login'))


@app.route('/ip/create', methods=['GET', 'POST'])
@require_auth_token
@require_role(UserRole.RESEARCHER)
def ip_create():
    form = IPCreateForm()
    if form.validate_on_submit():
        # create new ip instance and add to db
        new_ip = IP(
            category=form.category.data,
            subcategory=form.subcategory.data,
            short_description=form.short_description.data,
            elaborate_description=form.elaborate_description.data,
        )
        # handle file upload
        attachments = []
        for file in request.files.getlist('attachments'):
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                attachments.append(filename)
        new_ip.attachments = ', '.join(attachments)
        db.session.add(new_ip)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('ip_create.html', form=form)

@app.route('/ip/<int:ip_id>')
def ip_detail(ip_id):
    ip = IP.query.get(ip_id)
    return render_template('ip_detail.html', ip=ip)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # successful login
            print("Successful login!")
            flash('Login successful!', 'success')

            # generate and store authentication token
            auth_token = user.generate_auth_token()
            session['auth_token'] = auth_token
            session['username'] = username

            return redirect(url_for('home'))
        else:
            # failed login
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    print("mei logout mei aa gaya")
    print("session data", session)
    flash('You have been logged out.', 'info')
    if 'auth_token' in session:
        auth_token = session.pop('auth_token', None)
        if auth_token:
            # update the user record in the database
            user = User.query.filter_by(auth_token=auth_token).first()
            if user:
                user.auth_token = None
                db.session.commit()
            else:
                # user is not found
                pass
        
    return jsonify({'success': True})

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            password=form.password.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/user_profile/<username>', methods=['GET', 'POST'])
@require_auth_token
def user_profile(username):
    user = User.query.filter_by(username=username).first()
    if user:
        form = UserProfileForm()

        if form.validate_on_submit():
            # Handle the form submission and update the user's profile data
            user.description = form.description.data

            # Handle profile picture upload
            if form.profile_picture.data:
                profile_picture = form.profile_picture.data
                if allowed_file(profile_picture.filename):
                    filename = secure_filename(profile_picture.filename)
                    file_path = os.path.join(app.config['PROFILE_PICTURE_UPLOAD_FOLDER'], filename)
                    profile_picture.save(file_path)
                    user.profile_picture = file_path  # Save the file path to the user's profile_picture field

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_profile', username=username))

        # Pre-fill the form with the user's current profile data
        form.description.data = user.description

        return render_template('user_profile.html', form=form, user=user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('home'))
