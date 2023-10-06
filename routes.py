from flask import render_template, url_for, redirect, flash, request, session, jsonify, send_file, abort
from app import app, db
from forms import IPCreateForm, IPSearchForm, RegistrationForm, LoginForm, UserProfileForm, CommentForm
from models import User, IP, Comment, Notification
from auth import require_auth_token, require_role, require_role_jwt
from roles import UserRole
import os, json, io
from werkzeug.utils import secure_filename
from sqlalchemy import desc
from flask_jwt_extended import create_access_token, jwt_required

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
                ips_to_approve = IP.query.filter_by(approved_admin=False, approved_reviewer=True, approved_verifier=True).all()
            if user_role == 'Reviewer':
                users_to_approve = User.query.filter_by(approved=False).all()
                ips_to_approve = IP.query.filter_by(approved_reviewer=False, approved_verifier=True).all()
            if user_role == 'Verifier':
                users_to_approve = User.query.filter_by(approved=False).all()
                ips_to_approve = IP.query.filter_by(approved_verifier=False).all()
                print("ye hai ips to approve by verifier", ips_to_approve)

            category_choices = [(row.category, row.category) for row in db.session.query(IP.category).distinct()]
            category_choices.insert(0, ('', 'IP Category'))
            form.category.choices = category_choices

            query = IP.query.filter_by(approved_admin=True).order_by(desc(IP.id)) 

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
            elif user_role == 'Reviewer':
                return render_template('home.html', form=form, ips=search_results, user_role=user_role, ips_to_approve=ips_to_approve)
            elif user_role == 'Verifier':
                return render_template('home.html', form=form, ips=search_results, user_role=user_role, ips_to_approve=ips_to_approve)
            else:
                return render_template('home.html', form=form, ips=search_results, user_role=user_role)

    flash('You need to be logged in to access this page.', 'info')
    return redirect(url_for('login'))


@app.route('/ip/create', methods=['GET', 'POST'])
@require_auth_token
# @jwt_required()
# @require_role_jwt(UserRole.RESEARCHER)
# @require_role(UserRole.RESEARCHER)
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
            approved_admin=False,
            approved_reviewer=False,
            approved_verifier=False
        )

        # Handle file upload and store attachments in the database as binary data
        attachments = []
        attachment_filenames = []
        attachment_mimetypes = []
        for file in request.files.getlist('attachments'):
            if file and allowed_file(file.filename):
                # Read the file content as binary data
                file_data = file.read()
                attachments.append(file_data)
                attachment_filenames.append(file.filename)
                attachment_mimetypes.append(file.mimetype)

        # store the binary data in the 'attachments' column
        new_ip.attachments = b'\x00'.join(attachments)  # Join binary data with a null byte separator

        # store attachment filenames and mimetypes as JSON-encoded strings
        new_ip.attachment_filenames = json.dumps(attachment_filenames)
        new_ip.attachment_mimetypes = json.dumps(attachment_mimetypes)

        db.session.add(new_ip)
        db.session.commit()
        flash('IP created successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('ip_create.html', form=form)

@app.route('/ip_detail/<int:ip_id>', methods=['GET', 'POST'])
def ip_detail(ip_id):
    # retrieve the IP object based on the 'ip_id' parameter
    ip = IP.query.get(ip_id)
    user_email = session.get('email')
    # create an instance of the CommentForm
    form = CommentForm()

    if form.validate_on_submit():
        comment_text = form.comment_text.data

        # create a new comment
        comment = Comment(text=comment_text, user_email=user_email, ip=ip)

        db.session.add(comment)
        db.session.commit()

        flash('Comment added successfully!', 'success')
        return redirect(url_for('ip_detail', ip_id=ip_id))

    # retrieve attachment filenames and mimetypes
    attachment_filenames = json.loads(ip.attachment_filenames)
    attachment_mimetypes = json.loads(ip.attachment_mimetypes)

    # create a list of attachments with filenames and mimetypes
    attachments = zip(attachment_filenames, attachment_mimetypes)

    return render_template('ip_detail.html', ip=ip, form=form, attachments=attachments)



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

                # Generate JWT token
                access_token = create_access_token(identity=user.email)
                print("ye hai jwt access token", access_token)
                # Store the JWT token in a cookie (optional but recommended)
                response = jsonify({'access_token': access_token})
                response.set_cookie('access_token_cookie', access_token, httponly=True)

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
        # fetch the number of new notifications and mark them as viewed
        new_notifications = Notification.query.filter_by(user=user, viewed=False).all()
        print("ye hai naye wale notifications", new_notifications)
        for notification in new_notifications:
            notification.viewed = True
        db.session.commit()
        new_notifications_count = len(new_notifications)

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

        return render_template('user_profile.html', form=form, user=user, notifications=user.notifications, new_notifications_count=new_notifications_count)
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
def ip_approve_admin(email):
    print("this is the email")
    ip = IP.query.filter_by(user_email=email, approved_admin=False, approved_reviewer=True, approved_verifier=True).first()
    print("ye hai ip jo baki hai", ip)
    if ip:
        ip.approved_admin = True
        db.session.commit()
        flash(f'User "{ip.user_email}" has been approved.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('home'))

@app.route('/reviewer/approve_ip/<email>', methods=['GET', 'POST'])
@require_auth_token
@require_role(UserRole.REVIEWER)
def ip_approve_reviewer(email):
    print("this is the email")
    ip = IP.query.filter_by(user_email=email, approved_reviewer=False, approved_verifier=True).first()
    print("ye hai ip jo baki hai", ip)
    if ip:
        ip.approved_reviewer = True
        db.session.commit()
        flash(f'User "{ip.user_email}" has been approved.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('home'))

@app.route('/verifier/approve_ip/<email>', methods=['GET', 'POST'])
@require_auth_token
@require_role(UserRole.VERIFIER)
def ip_approve_verifier(email):
    print("this is the email")
    ip = IP.query.filter_by(user_email=email, approved_verifier=False).first()
    print("ye hai ip jo baki hai", ip)
    if ip:
        ip.approved_verifier = True
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
                user.skills = ""
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

@app.route('/add_comment/<ip_id>', methods=['POST'])
@require_auth_token
def add_comment(ip_id):
    user_email = session.get('email')
    ip = IP.query.get(ip_id)
    if user_email and ip:
        new_comment_text = request.form.get('comment_text')
        if new_comment_text:
            comment = Comment(text=new_comment_text, user_email=user_email, ip=ip)
            db.session.add(comment)
            db.session.commit()
            # create a notification for the IP owner
            notification_text = f'New comment on your IP: {ip.short_description}'
            notification = Notification(text=notification_text, user=ip.user)
            db.session.add(notification)
            db.session.commit()
            flash('Comment added successfully!', 'success')
        else:
            flash('Invalid comment.', 'danger')
    else:
        flash('User or IP not found.', 'danger')
    return redirect(url_for('ip_detail', ip_id=ip_id))

@app.route('/ip/download_attachment/<int:ip_id>/<attachment_filename>', methods=['GET'])
def download_attachment(ip_id, attachment_filename):
    # retrieve the IP object based on the ip_id
    ip = IP.query.get(ip_id)

    if ip is None:
        # IP not found, return a 404 Not Found response
        abort(404)

    # deserialize the attachment filenames and mimetypes using json.loads
    attachment_filenames = json.loads(ip.attachment_filenames)
    attachment_mimetypes = json.loads(ip.attachment_mimetypes)

    # find the index of the selected attachment
    try:
        attachment_index = attachment_filenames.index(attachment_filename)
    except ValueError:
        # attachment filename not found, return a 404 Not Found response
        abort(404)

    # get the selected attachment filename and mimetype
    mimetype = attachment_mimetypes[attachment_index]

    # retrieve the binary attachment data from the 'attachments' column
    attachments = ip.attachments.split(b'\x00')

    if (
        attachment_index < 0
        or attachment_index >= len(attachments)
    ):
        # invalid attachment index, return a 404 Not Found response
        abort(404)

    # get the selected attachment data
    attachment_data = attachments[attachment_index]

    # create a response to serve the attachment as a file download with the original filename and mimetype
    response = send_file(
        io.BytesIO(attachment_data),
        as_attachment=True,
        download_name=attachment_filename,
        mimetype=mimetype
    )

    return response
