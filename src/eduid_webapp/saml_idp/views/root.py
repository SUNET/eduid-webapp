# -*- coding: utf-8 -*-
from flask import Blueprint

__author__ = 'lundberg'

root_views = Blueprint('root', __name__, url_prefix='', template_folder='templates')


@root_views.route('/', methods=['GET'])
def index():
    # TODO: Redirect to landing page?
    return "hello idp"
