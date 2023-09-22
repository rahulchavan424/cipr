from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from sqlalchemy_utils import ChoiceType
from roles import UserRole
from sqlalchemy.orm import relationship

class User(db.Model):
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False, primary_key=True)
    roles = [
        (UserRole.ADMINISTRATOR, 'Administrator'),
        (UserRole.REVIEWER, 'Reviewer'),
        (UserRole.VERIFIER, 'Verifier'),
        (UserRole.RESEARCHER, 'Researcher')
    ]
    role = db.Column(ChoiceType(roles, impl=db.String()), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    auth_token = db.Column(db.String(32), unique=True, nullable=True)
    approved = db.Column(db.Boolean)
    profile_picture = db.Column(db.String(255))
    skills = db.Column(db.String(255), nullable=True)
    research_info = db.Column(db.Text, nullable=True)
    ips = relationship('IP', back_populates='user')
    
    def __init__(self, username, email, role, password, approved):
        self.username = username
        self.email = email
        self.role = role
        self.password_hash = generate_password_hash(password)
        self.approved = approved
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_auth_token(self):
        token = secrets.token_hex(16)
        self.auth_token = token
        db.session.commit()
        return token

class IP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    subcategory = db.Column(db.String(100), nullable=False)
    short_description = db.Column(db.String(255), nullable=False)
    elaborate_description = db.Column(db.Text, nullable=False)
    attachments = db.Column(db.String(255))
    user_email = db.Column(db.String(100), db.ForeignKey('user.email'))
    approved = db.Column(db.Boolean, default=False)
    user = relationship('User', back_populates='ips')