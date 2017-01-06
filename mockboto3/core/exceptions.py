from botocore.exceptions import ClientError


class MockClientError(ClientError):
    """Mock Client error."""
