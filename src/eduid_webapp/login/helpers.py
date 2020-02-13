# -*- coding: utf-8 -*-

from enum import Enum, unique

__author__ = 'lundberg'


@unique
class LoginMsg(Enum):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """
    # Explanation of message
    message_name = 'login.message_name'
