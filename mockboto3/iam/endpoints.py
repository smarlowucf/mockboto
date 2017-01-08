# -*- coding: utf-8 -*-

""""Mocked endpoints."""

from functools import wraps
from unittest.mock import patch

from mockboto3.core.exceptions import client_error
from mockboto3.core.utils import inflection

from mockboto3.iam import responses
from mockboto3.iam.models import AccessKey, Group, User


class MockIam(object):
    """Class for mocking iam endpoints."""

    def __init__(self):
        """Initialize class."""
        super(MockIam, self).__init__()
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
        self._check_user_exists(kwarg['UserName'], 'AddUserToGroup')
        self._check_group_exists(kwarg['GroupName'], 'AddUserToGroup')

        user = self.users[kwarg['UserName']]
        group = self.groups[kwarg['GroupName']]

        group.add_user(user.username)
        user.add_group(group.name)
        return responses.user_group_response()

    def create_access_key(self, kwarg):
        """Create access key for user if user exists."""
        self._check_user_exists(kwarg['UserName'], 'CreateAccessKey')

        access_key = AccessKey(kwarg['UserName'])
        self.access_keys[access_key.id] = access_key
        return responses.access_key_response(access_key)

    def create_group(self, kwarg):
        """Create group if it does not exist."""
        if kwarg['GroupName'] in self.groups:
            raise client_error('CreateGroup',
                               'EntityAlreadyExists',
                               'Group with name %s already exists.'
                               % kwarg['GroupName'])

        group = Group(kwarg['GroupName'])
        self.groups[group.name] = group
        return responses.group_response(group.name, group.id)

    def create_login_profile(self, kwarg):
        """Create login profile for user if user has no password."""
        self._check_user_exists(kwarg['UserName'], 'CreateLoginProfile')

        user = self.users[kwarg['UserName']]
        if user.login_profile:
            raise client_error('CreateLoginProfile',
                               'EntityAlreadyExists',
                               'LoginProfile for user with name %s '
                               'already exists.' % user.username)

        reset_required = kwarg.get('PasswordResetRequired', None)
        user.create_login_profile(kwarg['Password'],
                                  reset_required=reset_required)
        return responses.login_profile_response(user, create=True)

    def create_user(self, kwarg):
        """Create user if user does not exist."""
        if kwarg['UserName'] in self.users:
            raise client_error('CreateUser',
                               'EntityAlreadyExists',
                               'User with name %s already exists.'
                               % kwarg['UserName'])

        self.users[kwarg['UserName']] = User(kwarg['UserName'])
        return responses.user_response(kwarg['UserName'])

    def enable_mfa_device(self, kwarg):
        """Enable MFA Device for user."""
        self._check_user_exists(kwarg['UserName'], 'EnableMFADevice')

        user = self.users[kwarg['UserName']]
        if kwarg['SerialNumber'] in user.mfa_devices:
            raise client_error('EnableMFADevice',
                               'EntityAlreadyExists',
                               'Device with serial number %s already '
                               'exists.' % kwarg['SerialNumber'])

        user.enable_mfa_device(kwarg['SerialNumber'])
        return responses.generic_response()

    def deactivate_mfa_device(self, kwarg):
        """Deactivate and detach MFA Device from user if device exists."""
        self._check_user_exists(kwarg['UserName'], 'DeactivateMFADevice')

        user = self.users[kwarg['UserName']]
        if kwarg['SerialNumber'] not in user.mfa_devices:
            raise client_error('DeactivateMFADevice',
                               'NoSuchEntity',
                               'Device with serial number %s cannot '
                               'be found.' % kwarg['SerialNumber'])

        user.deactivate_mfa_device(kwarg['SerialNumber'])
        return responses.generic_response()

    def delete_access_key(self, kwarg):
        """Delete access key if access key exists."""
        try:
            self.access_keys.pop(kwarg['AccessKeyId'])
        except KeyError:
            self._access_key_not_found(kwarg['AccessKeyId'],
                                       'DeleteAccessKey')

        return responses.generic_response()

    def delete_group(self, kwarg):
        """Delete group if group exists."""
        self._check_group_exists(kwarg['GroupName'], 'DeleteGroup')

        for key, user in self.users.items():
            if kwarg['GroupName'] in user.groups:
                user.remove_group(kwarg['GroupName'])

        self.groups.pop(kwarg['GroupName'], None)
        return responses.generic_response()

    def delete_login_profile(self, kwarg):
        """Delete login profile (password) from user if users has password."""
        self._check_user_exists(kwarg['UserName'], 'DeleteLoginProfile')

        user = self.users[kwarg['UserName']]
        if not user.login_profile:
            self._login_profile_not_found(user.username, 'DeleteLoginProfile')

        user.delete_login_profile()
        return responses.generic_response()

    def delete_signing_certificate(self, kwarg):
        """Delete signing cert if cert exists."""
        user = self.users[kwarg['UserName']]
        if kwarg['CertificateId'] not in user.signing_certs:
            raise client_error('DeleteSigningCertificate',
                               '404',
                               'Signing certificate not found')

        user.signing_certs.remove(kwarg['CertificateId'])
        return responses.generic_response()

    def delete_user(self, kwarg):
        """Delete user if user exists."""
        self._check_user_exists(kwarg['UserName'], 'DeleteUser')

        for group in self.groups:
            if kwarg['UserName'] in group.users:
                group.remove_user(kwarg['UserName'])

        self.users.pop(kwarg['UserName'], None)
        return responses.generic_response()

    def detach_user_policy(self, kwarg):
        """Detach user policy if policy exists."""
        user = self.users[kwarg['UserName']]
        policy = kwarg['PolicyArn'].split('/')[1]

        if policy not in user.attached_policies:
            raise client_error('DetachUserPolicy',
                               '404',
                               'Attached policy not found')

        user.attached_policies.remove(policy)
        return responses.generic_response()

    def get_access_key_last_used(self, kwarg):
        try:
            access_key = self.access_keys.get(kwarg['AccessKeyId'])
        except KeyError:
            self._access_key_not_found(kwarg['AccessKeyId'],
                                       'GetAccessKeyLastUsed')

        return responses.access_key_last_used_response(access_key)

    def get_login_profile(self, kwarg):
        """Get login profile (password) for user if users has password."""
        self._check_user_exists(kwarg['UserName'], 'GetLoginProfile')

        user = self.users[kwarg['UserName']]
        if not user.login_profile:
            self._login_profile_not_found(user.username, 'GetLoginProfile')

        return responses.login_profile_response(user)

    def get_user(self, kwarg):
        """Get user if user exists."""
        self._check_user_exists(kwarg['UserName'], 'GetUser')

        return responses.user_response(kwarg['UserName'])

    def list_access_keys(self, kwarg):
        """List all of the users access keys if user exists."""
        self._check_user_exists(kwarg['UserName'], 'ListAccessKeys')

        keys = dict((access_key.id, access_key) for key, access_key
                    in self.access_keys.items()
                    if access_key.username == kwarg['UserName'])
        return responses.list_access_keys_response(keys)

    def list_attached_user_policies(self, kwarg):
        """List all of the users attached policies if user exists."""
        self._check_user_exists(kwarg['UserName'], 'ListAttachedUserPolicies')

        policies = self.users[kwarg['UserName']].attached_policies
        return responses.list_attached_policies_response(policies)

    def list_groups(self, kwarg):
        """List all groups"""
        return responses.list_groups_response(self.groups)

    def list_groups_for_user(self, kwarg):
        """List all of the users groups if user exists."""
        self._check_user_exists(kwarg['UserName'], 'ListGroupsForUser')

        groups = [self.groups[name] for name in
                  self.users[kwarg['UserName']].groups]
        return responses.list_groups_for_user_response(groups)

    def list_mfa_devices(self, kwarg):
        """List all of the users MFA devices if user exists."""
        self._check_user_exists(kwarg['UserName'], 'ListMFADevices')

        devices = self.users[kwarg['UserName']].mfa_devices
        return responses.list_mfa_devices_response(kwarg['UserName'], devices)

    def list_signing_certificates(self, kwarg):
        """List all of the users signing certs if the user exists."""
        self._check_user_exists(kwarg, 'ListSigningCertificates')

        certs = self.users[kwarg['UserName']].signing_certs
        return responses.list_signing_certs_response(kwarg['UserName'], certs)

    def list_users(self, kwarg):
        """List all users."""
        return responses.list_users_response(self.users)

    def remove_user_from_group(self, kwarg):
        """Remove user from group if user exists."""
        self._check_user_exists(kwarg['UserName'], 'RemoveUserFromGroup')
        self._check_group_exists(kwarg['GroupName'], 'RemoveUserFromGroup')

        group = self.groups[kwarg['GroupName']]
        user = self.users[kwarg['UserName']]

        group.remove_user(kwarg['UserName'])
        user.remove_group(kwarg['GroupName'])
        return responses.generic_response()

    def update_access_key(self, kwarg):
        try:
            access_key = self.access_keys.get(kwarg['AccessKeyId'])
        except KeyError:
            self._access_key_not_found(kwarg['AccessKeyId'],
                                       'UpdateAccessKey')

        access_key.status = kwarg['Status']
        return responses.generic_response()

    def update_login_profile(self, kwarg):
        """Update login profile for user."""
        self._check_user_exists(kwarg['UserName'], 'UpdateLoginProfile')

        user = self.users[kwarg['UserName']]
        if not user.login_profile:
            self._login_profile_not_found(user.username, 'UpdateLoginProfile')

        reset_required = kwarg.get('PasswordResetRequired', None)
        password = kwarg.get('Password', None)
        user.update_login_profile(password=password,
                                  reset_required=reset_required)
        return responses.generic_response()

    def _check_user_exists(self, user, method):
        try:
            self.users[user]
        except KeyError:
            raise client_error(method,
                               'NoSuchEntity',
                               'The user with name %s cannot be found.'
                               % user)

    def _check_group_exists(self, group, method):
        try:
            self.groups[group]
        except KeyError:
            raise client_error(method,
                               'NoSuchEntity',
                               'The group with name %s cannot be found.'
                               % group)

    @staticmethod
    def _access_key_not_found(access_key_id, method):
        raise client_error(method,
                           'NoSuchEntity',
                           'The Access Key with id %s cannot be found.'
                           % access_key_id)

    @staticmethod
    def _login_profile_not_found(user, method):
        raise client_error(method,
                           'NoSuchEntity',
                           'LoginProfile for user with name %s'
                           ' cannot be found.' % user)


def mock_iam(test):
    @wraps(test)
    def wrapper(*args, **kwargs):
        mocker = MockIam()
        with patch('botocore.client.BaseClient._make_api_call',
                   new=mocker.mock_make_api_call):
            test(*args, **kwargs)
    return wrapper
