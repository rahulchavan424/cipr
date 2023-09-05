from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, SelectField, MultipleFileField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class IPCreateForm(FlaskForm):
    category = StringField('IP Category', validators=[DataRequired()])
    subcategory = StringField('IP Sub Category', validators=[DataRequired()])
    short_description = StringField('IP Short Description', validators=[DataRequired()])
    elaborate_description = TextAreaField('IP Elaborate Description', validators=[DataRequired()])
    attachments = MultipleFileField('Attachments')
    submit = SubmitField('Submit')

class IPSearchForm(FlaskForm):
    search_query = StringField('Search', validators=[DataRequired()])
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
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')