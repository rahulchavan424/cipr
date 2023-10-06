from flask import redirect, url_for, session, flash
from models import User
from functools import wraps
from flask_jwt_extended import jwt_required, get_jwt_identity

# authentication logic
def require_auth_token(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        auth_token = session.get('auth_token')
        if auth_token:
            user = User.query.filter_by(auth_token=auth_token).first()
            if user:
                return view_func(*args, **kwargs)
        flash('Authentication required.', 'error')
        return redirect(url_for('login'))
    return wrapped_view

# authorization logic
def require_role(role_required):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth_token = session.get('auth_token')
            if auth_token:
                user = User.query.filter_by(auth_token=auth_token).first()
                if user and user.role == role_required:
                    return func(*args, **kwargs)
            flash('Access denied. You do not have the required role.', 'error')
            return redirect(url_for('home'))
        return wrapper
    return decorator

# jwt authorization
def require_role_jwt(role_required):
    def decorator(func):
        @wraps(func)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user_email = get_jwt_identity()
            print("ye hai jwt identity", current_user_email)
            user = User.query.filter_by(email=current_user_email).first()
            if user and user.role == role_required:
                return func(*args, **kwargs)
            flash('Access denied. You do not have the required role.', 'error')
            return redirect(url_for('home'))
        return wrapper
    return decorator