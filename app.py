from flask import Flask, render_template, flash, redirect, url_for, request, abort
from config import Config

# Imports for Flask Form
from flask_wtf import FlaskForm
from wtforms import (StringField, IntegerField, BooleanField, TextAreaField, PasswordField, SubmitField)
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import ValidationError

# Imports for Login
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user, login_required, logout_user, current_user

# Imports for SQL DATABASE
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Imports for Password hashing
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
Migrate(app,db)

################## LOGIN MANAGER CONFIG ##########################################
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

################################### Models #####################################################
class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    f_name = db.Column(db.String())
    l_name = db.Column(db.String())
    email = db.Column(db.String(100), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    todo = db.relationship('Todo', backref='author', lazy='dynamic')

    def __init__(self, f_name, l_name, email, password):
        self.f_name = f_name
        self.l_name = l_name
        self.email = email
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def __repr__(self):
        return self.username

class Todo(db.Model):
    __tablename__ = 'todo'

    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, task, complete, user_id):
        self.task = task
        self.complete = complete
        self.user_id = user_id

    def __repr__(self):
        return self.task

################################## Forms ################################################
class RegisterForm(FlaskForm):
    f_name = StringField('First Name', validators=[DataRequired()])
    l_name = StringField('Last Name')
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('cnf_password', message='Password must match!')])
    cnf_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def check_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Your email has been already registered!')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign in')

class AddForm(FlaskForm):
    task = StringField()
    submit = SubmitField('Add')

################################## Views ################################################
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    form = AddForm()
    incomplete_todo = Todo.query.filter_by(complete=False).filter_by(user_id=current_user.id).all()
    complete_todo = Todo.query.filter_by(complete=True).filter_by(user_id=current_user.id).all()
    if form.validate_on_submit():
        new_todo = Todo(task=form.task.data, complete=False, user_id=current_user.id)
        db.session.add(new_todo)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('index.html', form=form, incomplete_todo=incomplete_todo, complete_todo=complete_todo)

@app.route('/delete/<string:id>', methods=['GET', 'POST'])
def delete(id):
    todo = Todo.query.get(id)
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/complete/<string:id>', methods=['GET', 'POST'])
def complete(id):
    todo = Todo.query.filter_by(id=int(id)).first()
    todo.complete = True
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/uncomplete/<string:id>', methods=['GET', 'POST'])
def uncomplete(id):
    todo = Todo.query.filter_by(id=int(id)).first()
    todo.complete = False
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(f_name=form.f_name.data,
                    l_name=form.l_name.data,
                    email=form.email.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/reset_password_request')
def reset_password_request():
    return render_template('reset_password_request.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)
