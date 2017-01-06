""""Iam Classes."""

from datetime import datetime, timezone

from mockboto3.core.utils import get_random_string


class AccessKey(object):
    """Access Key class used for mocking AWS backend"""

    def __init__(self, user_name):
        super(AccessKey, self).__init__()
        self.id = get_random_string(length=20)
        self.key = get_random_string(length=40)
        self.status = "Active"
        self.username = user_name


class Group(object):
    """Group class used for mocking AWS backend group objects"""

    def __init__(self, name):
        super(Group, self).__init__()
        self.id = get_random_string(length=10)
        self.name = name
        self.users = []


class User(object):
    """User class used for mocking AWS backend user objects."""

    def __init__(self, user_name):
        super(User, self).__init__()
        self.id = get_random_string(length=10)
        self.attached_policies = []
        self.creation_date = datetime.now(timezone.utc)
        self.password_last_used = None
        self.groups = []
        self.mfa_devices = []
        self.password = None
        self.signing_certs = []
        self.username = user_name
