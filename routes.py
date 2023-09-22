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
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png'}
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
            user_role = user.role
            if user_role == 'Administrator':
                users_to_approve = User.query.filter_by(approved=False).all()
                ips_to_approve = IP.query.filter_by(approved=False).all()
                print("ye hai users to approve wale", users_to_approve)
                print("ye hai ips to approve wale", ips_to_approve)

            category_choices = [(row.category, row.category) for row in db.session.query(IP.category).distinct()]
            category_choices.insert(0, ('', 'IP Category'))
            form.category.choices = category_choices

            query = IP.query.filter_by(approved=True).order_by(desc(IP.id)) 

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
            
            if user_role == 'Administrator':
                return render_template('home.html', form=form, ips=search_results, user_role=user_role, users_to_approve=users_to_approve, ips_to_approve=ips_to_approve)
            else:
                return render_template('home.html', form=form, ips=search_results, user_role=user_role)

    flash('You need to be logged in to access this page.', 'info')
    return redirect(url_for('login'))


@app.route('/ip/create', methods=['GET', 'POST'])
@require_auth_token
@require_role(UserRole.RESEARCHER)
def ip_create():
    form = IPCreateForm()
    if form.validate_on_submit():
        # get the email address of the logged-in user from the session
        user_email = session.get('email')

        if not user_email:
            flash('User email not found. Please log in.', 'error')
            return redirect(url_for('login'))

        # create a new IP instance and add it to the database
        new_ip = IP(
            category=form.category.data,
            subcategory=form.subcategory.data,
            short_description=form.short_description.data,
            elaborate_description=form.elaborate_description.data,
            user_email=user_email,
            approved=False
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
        flash('IP created successfully!', 'success')
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
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if user.approved:
                # successful login
                print("Successful login!")
                flash('Login successful!', 'success')

                # generate and store authentication token
                auth_token = user.generate_auth_token()
                session['auth_token'] = auth_token
                session['email'] = email

                return redirect(url_for('home'))
            else:
                flash('Your account is pending approval by an administrator.', 'warning')
        else:
            # failed login
            flash('Invalid email or password', 'error')

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
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already exists. Please choose a different email.', 'danger')
            return redirect(url_for('register'))
        
        # check if the user's role is 'Administrator'
        if form.role.data == 'Administrator':
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                role=form.role.data,
                password=form.password.data,
                approved=True
            )
        else:
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                role=form.role.data,
                password=form.password.data,
                approved=False
            )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/user_profile/<email>', methods=['GET', 'POST'])
@require_auth_token
def user_profile(email):
    user = User.query.filter_by(email=email).first()
    if user:
        form = UserProfileForm()

        # handle profile picture upload
        if form.profile_picture.data:
            print("profile ke logic me aaya")
            profile_picture = form.profile_picture.data
            print("profile picture ka data", profile_picture)
            if allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                file_path = os.path.join(app.config['IMAGE_FOLDER'], filename)
                profile_picture.save(file_path)
                
                # save the file path to the user's profile_picture field in the database
                user.profile_picture = filename

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_profile', email=email))

        # pre-fill the form with the user's current profile data
        form.research_info.data = user.research_info

        return render_template('user_profile.html', form=form, user=user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('home'))
    
@app.route('/admin/approve_user/<email>', methods=['POST'])
@require_auth_token
@require_role(UserRole.ADMINISTRATOR)
def approve_user(email):
    print("this is the email")
    user = User.query.filter_by(email=email).first()
    if user:
        user.approved = True
        db.session.commit()
        flash(f'User "{user.email}" has been approved.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('home'))

@app.route('/admin/approve_ip/<email>', methods=['GET', 'POST'])
@require_auth_token
@require_role(UserRole.ADMINISTRATOR)
def ip_approve(email):
    print("this is the email")
    ip = IP.query.filter_by(user_email=email, approved=False).first()
    print("ye hai ip jo baki hai", ip)
    if ip:
        ip.approved = True
        db.session.commit()
        flash(f'User "{ip.user_email}" has been approved.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('home'))

@app.route('/add_skill/<email>', methods=['POST'])
@require_auth_token
def add_skill(email):
    user = User.query.filter_by(email=email).first()
    if user:
        new_skill = request.form.get('skill')
        if new_skill:
            if user.skills is None:
                user.skills = []
            user.skills = user.skills.split()
            print("ye honi chaiyye skills ki list", user.skills)
            user.skills.append(new_skill)
            user.skills = " ".join(user.skills)
            print("ye hai user ke skills" ,user.skills)
            db.session.commit()
            flash(f'Skill "{new_skill}" added successfully!', 'success')
        else:
            flash('Invalid skill name.', 'danger')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('user_profile', email=email))

@app.route('/remove_skill/<email>/<skill>', methods=['GET'])
@require_auth_token
def remove_skill(email, skill):
    user = User.query.filter_by(email=email).first()
    if user:
        if user.skills:
            skills_list = user.skills.split()
            if skill in skills_list:
                skills_list.remove(skill)
                user.skills = " ".join(skills_list)
                db.session.commit()
                flash(f'Skill "{skill}" removed successfully!', 'success')
            else:
                flash(f'Skill "{skill}" not found in user skills.', 'danger')
        else:
            flash('User has no skills to remove.', 'danger')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('user_profile', email=email))

@app.route('/edit_research_info/<email>', methods=['POST'])
@require_auth_token
def edit_research_info(email):
    user = User.query.filter_by(email=email).first()
    if user:
        new_research_info = request.form.get('research_info')
        if new_research_info is not None:
            user.research_info = new_research_info
            db.session.commit()
            flash('Research info updated successfully!', 'success')
        else:
            flash('Invalid research info.', 'danger')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('user_profile', email=email))
