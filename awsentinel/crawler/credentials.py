import aioboto3
from typing import Optional
import logging

logger = logging.getLogger("awsentinel.credentials")


class AWSClientManager:
    """Manages AWS session resolution, cross-account AssumeRole support, and credential validation."""

    def __init__(self, profile: Optional[str] = None, role_arn: Optional[str] = None):
        self.profile = profile
        self.role_arn = role_arn
        self.session: Optional[aioboto3.Session] = None

    async def get_session(self) -> aioboto3.Session:
        """Resolves and returns a shared, fully authenticated aioboto3.Session."""
        if self.session is not None:
            return self.session

        # 1. Initialize session resolving environment variables or profile
        if self.profile:
            session = aioboto3.Session(profile_name=self.profile)
        else:
            session = aioboto3.Session()

        # 2. Perform AssumeRole if a target cross-account role ARN is specified
        if self.role_arn:
            logger.info(f"Attempting to assume role: {self.role_arn}")
            async with session.client("sts") as sts_client:
                try:
                    response = await sts_client.assume_role(
                        RoleArn=self.role_arn,
                        RoleSessionName="AWSentinelScanSession",
                    )
                except Exception as e:
                    logger.error(f"Failed to assume role {self.role_arn}: {e}")
                    raise RuntimeError(
                        f"AssumeRole failed for {self.role_arn}: {e}"
                    ) from e

                credentials = response["Credentials"]
                # Spawn session with temporary credentials
                self.session = aioboto3.Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )
        else:
            self.session = session

        return self.session

    async def validate_credentials(self) -> str:
        """Validates credentials using sts.get_caller_identity.

        Returns:
            The AWS Account ID.
        Raises:
            RuntimeError if authentication or caller identity retrieval fails.
        """
        session = await self.get_session()
        async with session.client("sts") as sts_client:
            try:
                response = await sts_client.get_caller_identity()
                account_id = response["Account"]
                logger.info(
                    f"Credentials successfully validated. Account: {account_id}"
                )
                return account_id
            except Exception as e:
                logger.error(f"Credential validation failed via STS: {e}")
                raise RuntimeError(
                    f"Credential verification failed. STS caller identity error: {e}"
                ) from e
