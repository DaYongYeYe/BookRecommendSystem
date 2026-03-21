from flask import Blueprint

bp = Blueprint('api', __name__)

from app.api import views  # noqa: E402,F401
from app.api import reader_views  # noqa: E402,F401

