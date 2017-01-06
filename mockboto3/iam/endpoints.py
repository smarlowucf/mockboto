""""Mocked endpoints."""

from functools import wraps

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from .constants import group_name, username
from .models import AccessKey, Group, User
from .responses import (access_key_response, group_response,
                        generic_response, list_access_keys_response,
                        list_attached_policies_response,
                        list_mfa_devices_response,
                        list_signing_certs_response, list_groups_response,
                        list_groups_for_user_response,
                        list_users_response, login_profile_response,
                        user_response, user_group_response)

from mockboto3.core.exceptions import client_error
from mockboto3.core.utils import inflection


class AWSMock(object):
    """Class for mocking AWS endpoints."""

    def __init__(self):
        """Initialize class."""
        super(AWSMock, self).__init__()
        self.access_keys = {}
        self.groups = {}
        self.users = {}

    def mock_make_api_call(self, operation_name, kwarg):
        """Entry point for mocking AWS endpoints.

        Calls the mocked AWS operation and returns a parsed
        response.

        If the AWS endpoint is not mocked raise a client error.
        """
        try:
            return getattr(self, inflection(operation_name))(kwarg)
        except AttributeError:
            raise client_error(operation_name,
                               'NoSuchMethod',
                               'Operation not mocked.')

    def add_user_to_group(self, kwarg):
        """Add user to the group if user and group exist."""
        self._check_user_exists(kwarg, 'AddUserToGroup')
        self._check_group_exists(kwarg, 'AddUserToGroup')

        user = self.users[kwarg[username]]
        group = self.groups[kwarg[group_name]]

        group.users.append(user.username)
        user.groups.append(group.name)
        return user_group_response()

    def create_access_key(self, kwarg):
        """Create access key for user if user exists."""
        self._check_user_exists(kwarg, 'CreateAccessKey')

        access_key = AccessKey(kwarg[username])
        self.access_keys[access_key.id] = access_key
        return access_key_response(access_key)

    def create_group(self, kwarg):
        """Create group if it does not exist."""
        if kwarg[group_name] in self.groups:
            raise client_error('CreateGroup',
                               'EntityAlreadyExists',
                               'Group with name %s already exists.'
                               % kwarg[group_name])

        group = Group(kwarg[group_name])
        self.groups[group.name] = group
        return group_response(group.name, group.id)

    def create_login_profile(self, kwarg):
        """Create login profile for user if user has no password."""
        user = self.users[kwarg[username]]
        if user.password:
            raise client_error('CreateLoginProfile',
                               '409',
                               'LoginProfile for %s exists' % user.username)

        user.password = kwarg['Password']
        return login_profile_response(user.username)

    def create_user(self, kwarg):
        """Create user if user does not exist."""
        if kwarg[username] in self.users:
            raise client_error('CreateUser',
                               'EntityAlreadyExists',
                               'User with name %s already exists.'
                               % kwarg[username])

        self.users[kwarg[username]] = User(kwarg[username])
        return user_response(kwarg[username])

    def deactivate_mfa_device(self, kwarg):
        """Deactivate and detach MFA Device from user if device exists."""
        user = self.users[kwarg[username]]
        if kwarg['SerialNumber'] not in user.mfa_devices:
            raise client_error('DeactivateMFADevice',
                               '404',
                               'Device not found')

        user.mfa_devices.remove(kwarg['SerialNumber'])
        return generic_response()

    def delete_access_key(self, kwarg):
        """Delete access key if access key exists."""
        try:
            self.access_keys.pop(kwarg['AccessKeyId'])
        except KeyError:
            self._access_key_not_found(kwarg['AccessKeyId'],
                                       'DeleteAccessKey')

        return generic_response()

    def delete_group(self, kwarg):
        """Delete group if group exists."""
        self._check_group_exists(kwarg, 'DeleteGroup')

        for key, user in self.users.items():
            if kwarg[group_name] in user.groups:
                user.groups.remove(kwarg[group_name])

        self.groups.pop(kwarg[group_name], None)
        return generic_response()

    def delete_login_profile(self, kwarg):
        """Delete login profile (password) from user if users has password."""
        user = self.users[kwarg[username]]
        if not user.password:
            raise client_error('DeleteLoginProfile',
                               '404',
                               'LoginProfile for %s not found' % user.username)

        user.password = None
        return generic_response()

    def delete_signing_certificate(self, kwarg):
        """Delete signing cert if cert exists."""
        user = self.users[kwarg[username]]
        if kwarg['CertificateId'] not in user.signing_certs:
            raise client_error('DeleteSigningCertificate',
                               '404',
                               'Signing certificate not found')

        user.signing_certs.remove(kwarg['CertificateId'])
        return generic_response()

    def delete_user(self, kwarg):
        """Delete user if user exists."""
        self._check_user_exists(kwarg, 'DeleteUser')

        for group in self.groups:
            if kwarg[username] in group.users:
                group.users.remove(kwarg[username])

        self.users.pop(kwarg[username], None)
        return generic_response()

    def detach_user_policy(self, kwarg):
        """Detach user policy if policy exists."""
        user = self.users[kwarg[username]]
        policy = kwarg['PolicyArn'].split('/')[1]

        if policy not in user.attached_policies:
            raise client_error('DetachUserPolicy',
                               '404',
                               'Attached policy not found')

        user.attached_policies.remove(policy)
        return generic_response()

    def get_user(self, kwarg):
        """Get user if user exists."""
        self._check_user_exists(kwarg, 'GetUser')

        return user_response(kwarg[username])

    def list_access_keys(self, kwarg):
        """List all of the users access keys if user exists."""
        self._check_user_exists(kwarg, 'ListAccessKeys')

        keys = dict((access_key.id, access_key) for key, access_key
                    in self.access_keys.items()
                    if access_key.username == kwarg[username])
        return list_access_keys_response(keys)

    def list_attached_user_policies(self, kwarg):
        """List all of the users attached policies if user exists."""
        self._check_user_exists(kwarg, 'ListAttachedUserPolicies')

        policies = self.users[kwarg[username]].attached_policies
        return list_attached_policies_response(policies)

    def list_groups(self, kwarg):
        """List all groups"""
        return list_groups_response(self.groups)

    def list_groups_for_user(self, kwarg):
        """List all of the users groups if user exists."""
        self._check_user_exists(kwarg, 'ListGroupsForUser')

        groups = [self.groups[name] for name in
                  self.users[kwarg[username]].groups]
        return list_groups_for_user_response(groups)

    def list_mfa_devices(self, kwarg):
        """List all of the users MFA devices if user exists."""
        self._check_user_exists(kwarg, 'ListMFADevices')

        devices = self.users[kwarg[username]].mfa_devices
        return list_mfa_devices_response(kwarg[username], devices)

    def list_signing_certificates(self, kwarg):
        """List all of the users signing certs if the user exists."""
        self._check_user_exists(kwarg, 'ListSigningCertificates')

        certs = self.users[kwarg[username]].signing_certs
        return list_signing_certs_response(kwarg[username], certs)

    def list_users(self, kwarg):
        """List all users."""
        return list_users_response(self.users)

    def remove_user_from_group(self, kwarg):
        """Remove user from group if user exists."""
        self._check_user_exists(kwarg, 'RemoveUserFromGroup')
        self._check_group_exists(kwarg, 'RemoveUserFromGroup')

        group = self.groups[kwarg[group_name]]
        user = self.users[kwarg[username]]

        group.users.remove(kwarg[username])
        user.groups.remove(kwarg[group_name])
        return generic_response()

    def update_access_key(self, kwarg):
        try:
            access_key = self.access_keys.get(kwarg['AccessKeyId'])
        except KeyError:
            self._access_key_not_found(kwarg['AccessKeyId'],
                                       'UpdateAccessKey')

        access_key.status = kwarg['Status']
        return generic_response()

    def _check_user_exists(self, kwarg, method):
        try:
            self.users[kwarg[username]]
        except KeyError:
            raise client_error(method,
                               'NoSuchEntity',
                               'The user with name %s cannot be found.'
                               % kwarg[username])

    def _check_group_exists(self, kwarg, method):
        try:
            self.groups[kwarg[group_name]]
        except KeyError:
            raise client_error(method,
                               'NoSuchEntity',
                               'The group with name %s cannot be found.'
                               % kwarg[group_name])

    @staticmethod
    def _access_key_not_found(access_key_id, method):
        raise client_error(method,
                           'NoSuchEntity',
                           'The Access Key with id %s cannot be found.'
                           % access_key_id)


def mock_iam(test):
    @wraps(test)
    def wrapper(*args, **kwargs):
        mocker = AWSMock()
        with patch('botocore.client.BaseClient._make_api_call',
                   new=mocker.mock_make_api_call):
            test(*args, **kwargs)
    return wrapper
