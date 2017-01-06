#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto3

from mockboto3.core.exceptions import MockBoto3ClientError
from mockboto3.iam.constants import group_name, username
from mockboto3.iam.endpoints import AWSMock, mock_iam

from nose.tools import assert_equal


class TestIam:

    @classmethod
    def setup_class(cls):
        cls.client = boto3.client('iam')
        cls.kwarg = {username: 'John',
                     group_name: 'Admins'}

    def test_unmocked_operation(self):
        """Test operation not mocked error is returned."""
        msg = 'An error occurred (NoSuchMethod) when calling the ' \
              'CreateGecko operation: Operation not mocked.'

        try:
            mocker = AWSMock()
            mocker.mock_make_api_call('CreateGecko',
                                      {'Name': 'gecko'})

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_get_user_exception(self):
        """Test get non existent user raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the GetUser' \
              ' operation: The user with name John cannot be found.'

        try:
            # Assert get non existing user exception
            self.client.get_user(UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_list_user_groups_exception(self):
        """Test list non existent user groups raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the ' \
              'ListGroupsForUser operation: The user with name ' \
              'John cannot be found.'

        try:
            # Assert list non existent user groups exception
            self.client.list_groups_for_user(UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_add_user_group_exception(self):
        """Test add user to non existent group raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the ' \
              'AddUserToGroup operation: The user with name John ' \
              'cannot be found.'

        try:
            # Assert add user to non existing group exception
            self.client.add_user_to_group(GroupName=self.kwarg[group_name],
                                          UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_delete_user_exception(self):
        """Test delete non existent user raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the' \
              ' DeleteUser operation: The user with name John cannot' \
              ' be found.'

        try:
            # Assert delete non existent user exception
            self.client.delete_user(UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_delete_group_exception(self):
        """Test delete non existent group raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the' \
              ' DeleteGroup operation: The group with name Admins' \
              ' cannot be found.'

        try:
            # Assert delete non existent user exception
            self.client.delete_group(GroupName=self.kwarg[group_name])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_remove_user_group_exception(self):
        """Test remove non existent user from group raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the' \
              ' RemoveUserFromGroup operation: The user with name' \
              ' John cannot be found.'

        try:
            # Assert remove non existent user from group exception
            self.client.remove_user_from_group(
                GroupName=self.kwarg[group_name],
                UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_user_group(self):
        """Test user and group endpoints."""
        # Create user and attempt to add user to group
        self.client.create_user(UserName=self.kwarg[username])

        msg = 'An error occurred (NoSuchEntity) when calling the ' \
              'AddUserToGroup operation: The group with name ' \
              'Admins cannot be found.'

        try:
            self.client.add_user_to_group(GroupName=self.kwarg[group_name],
                                          UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

        # Create group and add user to group
        self.client.create_group(GroupName=self.kwarg[group_name])
        self.client.add_user_to_group(GroupName=self.kwarg[group_name],
                                      UserName=self.kwarg[username])

        # Assert user and group exist and assert user in group
        assert_equal(self.client.list_users()['Users'][0][username],
                     self.kwarg[username])
        assert_equal(self.client.list_groups()['Groups'][0][group_name],
                     self.kwarg[group_name])
        assert_equal(self.kwarg[group_name],
                     self.client.list_groups_for_user(
                         UserName=self.kwarg[username]
                     )['Groups'][0][group_name])

        msg = 'An error occurred (EntityAlreadyExists) when calling the ' \
              'CreateGroup operation: Group with name Admins already exists.'

        try:
            # Assert create group exists raises exception
            self.client.create_group(GroupName=self.kwarg[group_name])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

        msg = 'An error occurred (EntityAlreadyExists) when calling the ' \
              'CreateUser operation: User with name John already exists.'

        try:
            # Assert create user exists raises exception
            self.client.create_user(UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

        # Get user response
        response = self.client.get_user(UserName=self.kwarg[username])
        assert_equal(response['User'][username], self.kwarg[username])

        # List groups for user response
        response = self.client.list_groups_for_user(
            GroupName=self.kwarg[group_name],
            UserName=self.kwarg[username])

        assert_equal(response['Groups'][0][group_name],
                     self.kwarg[group_name])
        assert_equal(1, len(response['Groups']))

        # Remove user from group
        self.client.remove_user_from_group(GroupName=self.kwarg[group_name],
                                           UserName=self.kwarg[username])
        assert_equal(0,
                     len(self.client.list_groups_for_user(
                         UserName=self.kwarg[username])['Groups']))

        # Delete group
        self.client.delete_group(GroupName=self.kwarg[group_name])
        assert_equal(0, len(self.client.list_groups()['Groups']))

        # Delete user
        self.client.delete_user(UserName=self.kwarg[username])
        assert_equal(0, len(self.client.list_users()['Users']))

    @mock_iam
    def test_create_access_key_exception(self):
        """Test create access key for non existent user raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the ' \
              'CreateAccessKey operation: The user with name John' \
              ' cannot be found.'

        try:
            # Assert create access key for non existent user exception
            self.client.create_access_key(UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_delete_access_key_exception(self):
        """Test delete non existent access key raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the ' \
              'DeleteAccessKey operation: The Access Key with id' \
              ' key1234567891234 cannot be found.'

        try:
            # Assert delete non existent access key exception
            self.client.delete_access_key(AccessKeyId='key1234567891234')

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_list_access_key_exception(self):
        """Test list access keys for non existent user raises exception."""
        msg = 'An error occurred (NoSuchEntity) when calling the ' \
              'ListAccessKeys operation: The user with name John' \
              ' cannot be found.'

        try:
            # Assert list access keys for non existent user exception
            self.client.list_access_keys(UserName=self.kwarg[username])

        except MockBoto3ClientError as e:
            assert_equal(msg, str(e))

    @mock_iam
    def test_access_key(self):
        """Test access key endpoints."""
        self.client.create_user(UserName=self.kwarg[username])
        response = self.client.create_access_key(
            UserName=self.kwarg[username]
        )

        # Get created key id
        key_id = response['AccessKey']['AccessKeyId']

        # Get user access keys
        response = self.client.list_access_keys(UserName=self.kwarg[username])

        # Assert id's are equal and keys length is 1
        assert_equal(1, len(response['AccessKeyMetadata']))
        assert_equal(key_id,
                     response['AccessKeyMetadata'][0]['AccessKeyId'])

        # Test UpdateAccessKey
        self.client.update_access_key(AccessKeyId=key_id, Status='Inactive')
        response = self.client.list_access_keys(UserName=self.kwarg[username])

        assert_equal('Inactive',
                     response['AccessKeyMetadata'][0]['Status'])

        # Delete access key
        self.client.delete_access_key(AccessKeyId=key_id)

        # Confirm deletion
        response = self.client.list_access_keys(UserName=self.kwarg[username])
        assert_equal(0, len(response['AccessKeyMetadata']))

    def test_test(self):
        """Test operation not mocked error is returned."""
        mocker = AWSMock()
        mocker.mock_make_api_call('CreateUser',
                                  {'UserName': self.kwarg[username]})
        mocker.mock_make_api_call('CreateAccessKey',
                                  {'UserName': self.kwarg[username],
                                   'AccessKeyId': 'key123'})
        mocker.mock_make_api_call('ListAccessKeys',
                                  {'UserName': 'John'})
