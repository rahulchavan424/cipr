from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cipr.db'
db = SQLAlchemy(app)

app.app_context().push()

from routes import *
from models import *

if __name__ == '__main__':
    app.run(debug=True)