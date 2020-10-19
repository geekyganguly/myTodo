import os
base_dir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = 'mysecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///'+ os.path.join(base_dir, 'data.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
