from flask import Blueprint

bp = Blueprint('rbac', __name__)

from app.rbac import views