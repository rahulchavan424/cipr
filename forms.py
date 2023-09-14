from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, SelectField, MultipleFileField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_wtf.file import FileField, FileAllowed

class IPCreateForm(FlaskForm):
    category = StringField('IP Category', validators=[DataRequired()])
    subcategory = StringField('IP Sub Category', validators=[DataRequired()])
    short_description = StringField('IP Short Description', validators=[DataRequired()])
    elaborate_description = TextAreaField('IP Elaborate Description', validators=[DataRequired()])
    attachments = MultipleFileField('Attachments')
    submit = SubmitField('Submit')

class IPSearchForm(FlaskForm):
    search_query = StringField('Search', validators=[DataRequired()])
    category = SelectField('Category')
    subcategory = SelectField('Subcategory')
    submit = SubmitField('Search')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role_choices = [
        ('Administrator', 'Administrator'),
        ('Reviewer', 'Reviewer'),
        ('Verifier', 'Verifier'),
        ('Researcher', 'Researcher')
    ]
    role = SelectField('Role', choices=role_choices, validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UserProfileForm(FlaskForm):
    profile_picture = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!'),
    ])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Save Profile')