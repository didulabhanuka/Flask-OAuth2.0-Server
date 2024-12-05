import os

class Config(object):

    basedir = os.path.abspath(os.path.dirname(__file__))

    # Set up the App SECRET_KEY
    SECRET_KEY = os.getenv('SECRET_KEY', '9#99maLvMKk2T4*tghA7og$m')

    HASH_ALGORITHM = 'HS256'
    
    def print_debug_info(self):
        print("Config base directory:", self.basedir)
        print("Current working directory:", os.getcwd())

class DebugConfig(Config):
    DEBUG = True

# Load all possible configurations
config_dict = {
    'Debug'     : DebugConfig
}
