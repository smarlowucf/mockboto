# -*- coding: utf-8 -*-

""""Iam Classes."""

from datetime import datetime, timezone

from mockboto3.core.utils import get_random_string


class AccessKey(object):
    """Access Key class used for mocking AWS backend"""

    def __init__(self, user_name):
        super(AccessKey, self).__init__()
        self.id = get_random_string(length=20)
        self.create_date = datetime.now(timezone.utc)
        self.key = get_random_string(length=40)
        self.last_used = AccessKeyLastUsed()
        self.status = "Active"
        self.username = user_name


class AccessKeyLastUsed(object):
    """Access Key Last Used for tracking how and when a key was used."""

    def __init__(self):
        super(AccessKeyLastUsed, self).__init__()
        self.date = datetime.now(timezone.utc)
        self.region = 'us-west-1'
        self.service_name = 'iam'


class Group(object):
    """Group class used for mocking AWS backend group objects"""

    def __init__(self, name):
        super(Group, self).__init__()
        self.id = get_random_string(length=10)
        self.create_date = datetime.now(timezone.utc)
        self.name = name
        self.users = []


class LoginProfile(object):
    """Login profile (password) for AWS User."""

    def __init__(self, password, reset_required=False):
        super(LoginProfile, self).__init__()
        self.password = password
        self.create_date = datetime.now(timezone.utc)
        self.reset_required = reset_required


class User(object):
    """User class used for mocking AWS backend user objects."""

    def __init__(self, user_name):
        super(User, self).__init__()
        self.id = get_random_string(length=10)
        self.attached_policies = []
        self.create_date = datetime.now(timezone.utc)
        self.groups = []
        self.login_profile = None
        self.mfa_devices = []
        self.password_last_used = None
        self.signing_certs = []
        self.username = user_name

    def create_login_profile(self, password, reset_required=False):
        self.login_profile = LoginProfile(password, reset_required)

    def delete_login_profile(self):
        self.login_profile = None

    def update_login_profile(self, password=None, reset_required=None):
        if password:
            self.login_profile.password = password
        if reset_required is not None:
            self.login_profile.reset_required = reset_required
