from flask import Blueprint

blueprint = Blueprint('apis_blueprint', __name__)

from . import routes  # Import routes after defining the blueprint
