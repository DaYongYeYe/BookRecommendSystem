from flask import Blueprint

bp = Blueprint('creator', __name__)

from app.creator import views  # noqa: E402,F401
