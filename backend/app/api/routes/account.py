from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlmodel import select
from typing import Optional, Dict, List, Any, Union, Literal
from datetime import datetime
import uuid
import logging
from app.api.deps.auth import CurrentUser, SessionDep
from app.models import User
from app.core.security import get_password_hash

# LinkedIn specific imports
import requests
import json
import time
from app.core.config import settings

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(tags=["linkedin"])


class LinkedInBasicAuth(BaseModel):
    """LinkedIn Basic Authentication model with username and password"""

    provider: Literal["LINKEDIN"]
    username: str
    password: str
    country: Optional[str] = None
    user_agent: Optional[str] = None
    disabled_features: Optional[List[str]] = None


class LinkedInCookieAuth(BaseModel):
    """LinkedIn Cookie Authentication model"""

    provider: Literal["LINKEDIN"]
    access_token: str  # li_at cookie
    premium_token: Optional[str] = None  # li_a cookie
    country: Optional[str] = None
    user_agent: Optional[str] = None
    disabled_features: Optional[List[str]] = None


class LinkedInAuthResponse(BaseModel):
    """Response model after successful LinkedIn authentication"""

    object: str = "AccountCreated"
    account_id: str


class LinkedInCheckpointResponse(BaseModel):
    """Response model for LinkedIn authentication challenge"""

    object: str = "Checkpoint"
    account_id: str
    checkpoint: Dict[str, Any]


class LinkedInAccountResponse(BaseModel):
    """Model for LinkedIn account information"""

    object: str = "Account"
    type: str = "LINKEDIN"
    id: str
    name: str
    created_at: datetime
    connection_params: Dict[str, Any]
    sources: List[Dict[str, Any]]
    groups: List[str] = []


class LinkedInCheckpointSolveRequest(BaseModel):
    """Request model for solving LinkedIn authentication challenges"""

    provider: Literal["LINKEDIN"]
    account_id: str
    code: str


class LinkedInClient:
    """Client class for LinkedIn API authentication"""

    BASE_URL = "https://www.linkedin.com/voyager/api"
    AUTH_BASE_URL = "https://www.linkedin.com"

    # Request headers for authentication
    REQUEST_HEADERS = {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        "accept-language": "en-US,en;q=0.9",
        "x-li-lang": "en_US",
        "x-restli-protocol-version": "2.0.0",
    }

    def __init__(self, debug=False, proxies=None):
        self.session = requests.session()
        self.session.headers.update(self.REQUEST_HEADERS)
        self.session.verify = not debug

        if proxies:
            self.session.proxies.update(proxies)

        self.logger = logger

    def _request_session_cookies(self):
        """Get initial session cookies from LinkedIn"""
        res = requests.get(
            f"{self.AUTH_BASE_URL}/uas/authenticate", headers=self.REQUEST_HEADERS
        )
        return res.cookies

    def _determine_challenge_type(self, challenge_url, response_data=None):
        """
        Determine the type of LinkedIn challenge based on URL patterns and response data

        Args:
            challenge_url (str): The challenge URL from LinkedIn
            response_data (dict): Optional response data that may contain additional hints

        Returns:
            str: The challenge type (OTP, PHONE_REGISTER, CAPTCHA, IN_APP_VALIDATION, 2FA, etc.)
        """
        # Parse the URL to extract path and parameters
        from urllib.parse import urlparse, parse_qs

        parsed_url = urlparse(challenge_url)
        path = parsed_url.path.lower()
        query_params = parse_qs(parsed_url.query)

        # Log the URL components for debugging
        self.logger.debug(f"Challenge URL path: {path}")
        self.logger.debug(f"Challenge URL params: {query_params}")

        # Check for specific patterns in the URL path

        # Direct login submit usually indicates OTP or email verification
        if "/checkpoint/lg/direct-login-submit" in path:
            # This is typically an OTP challenge sent to email
            return "OTP"

        # Phone verification patterns
        if any(
            pattern in path
            for pattern in [
                "/checkpoint/lg/phone-challenge",
                "/checkpoint/phone",
                "/phone-register",
                "/add-phone",
                "/checkpoint/lg/add-phone-number",
            ]
        ):
            return "PHONE_REGISTER"

        # Two-factor authentication patterns
        if any(
            pattern in path
            for pattern in [
                "/two-step-verification",
                "/checkpoint/lg/login-two-factor",
                "/checkpoint/lg/two-factor-auth",
                "/uas/two-factor-auth-checkpoint",
            ]
        ):
            return "2FA"

        # CAPTCHA patterns
        if any(
            pattern in path
            for pattern in [
                "/captcha",
                "/checkpoint/challenge/captcha",
                "/checkpoint/lg/captcha-challenge",
                "/uas/captcha-submit",
            ]
        ):
            return "CAPTCHA"

        # In-app validation patterns
        if any(
            pattern in path
            for pattern in [
                "/checkpoint/lg/login-in-app",
                "/mobile-app",
                "/checkpoint/lg/app-challenge",
                "/checkpoint/lg/mobile-validation",
            ]
        ):
            return "IN_APP_VALIDATION"

        # Email verification patterns (different from OTP)
        if any(
            pattern in path
            for pattern in [
                "/checkpoint/lg/email-pin-challenge",
                "/checkpoint/lg/verify-email",
                "/email-verification",
            ]
        ):
            return "EMAIL_VERIFICATION"

        # Security verification patterns
        if any(
            pattern in path
            for pattern in [
                "/checkpoint/lg/login-submit",
                "/checkpoint/lg/security-challenge",
                "/checkpoint/challenge/verify",
            ]
        ):
            # Could be various types, need to check other indicators
            # Check query parameters for more hints
            if "addDetailedLoginResult" in query_params:
                # This often indicates OTP
                return "OTP"
            return "SECURITY_VERIFICATION"

        # Rate limiting or suspicious activity
        if any(
            pattern in path
            for pattern in [
                "/checkpoint/lg/rate-limit",
                "/checkpoint/lg/suspicious-activity",
            ]
        ):
            return "RATE_LIMIT"

        # If we can't determine from URL, check response data if available
        if response_data:
            # Check for specific fields in the response that might indicate challenge type
            if response_data.get("phoneNumber"):
                return "PHONE_REGISTER"
            if response_data.get("captchaImage") or response_data.get(
                "captchaRequired"
            ):
                return "CAPTCHA"
            if response_data.get("twoFactorRequired"):
                return "2FA"
            if response_data.get("emailVerificationRequired"):
                return "EMAIL_VERIFICATION"

        # Default to UNKNOWN if we can't determine the type
        self.logger.warning(
            f"Could not determine challenge type for URL: {challenge_url}"
        )
        return "UNKNOWN"

    def authenticate_with_credentials(self, username, password):
        """Authenticate with LinkedIn using username and password"""
        cookies = self._request_session_cookies()
        self.session.cookies = cookies

        payload = {
            "session_key": username,
            "session_password": password,
            "JSESSIONID": self.session.cookies.get("JSESSIONID", ""),
        }

        # Authenticate
        res = self.session.post(f"{self.AUTH_BASE_URL}/uas/authenticate", data=payload)

        # Check response
        if res.status_code != 200:
            logger.error(
                f"LinkedIn authentication failed: {res.status_code} - {res.text}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="LinkedIn authentication failed. Invalid credentials.",
            )

        try:
            data = res.json()
            # Handle LinkedIn challenges
            if data and data.get("login_result") == "CHALLENGE":
                challenge_url = data.get("challenge_url", "")
                logger.info(f"LinkedIn challenge detected: {challenge_url}")

                # Determine the challenge type based on URL and response data
                challenge_type = self._determine_challenge_type(challenge_url, data)

                # Extract additional challenge metadata if available
                challenge_metadata = {
                    "challenge_id": data.get("challenge_id"),
                    "session_id": data.get("pSIdString"),
                    "csrf_token": data.get("csrfToken"),
                    "requires_phone": data.get("requiresPhone", False),
                    "requires_captcha": data.get("requiresCaptcha", False),
                }

                # Return challenge information instead of raising an exception
                return {
                    "status": "CHALLENGE",
                    "challenge_type": challenge_type,
                    "challenge_url": challenge_url,
                    "challenge_metadata": challenge_metadata,
                }

            # Handle other non-PASS login results
            elif data and data.get("login_result") != "PASS":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"LinkedIn authentication failed: {data.get('login_result')}",
                )
        except Exception as e:
            logger.error(f"Error processing LinkedIn authentication response: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error processing LinkedIn authentication response",
            )

        # Extract the li_at cookie which is the access token
        li_at = self.session.cookies.get("li_at", "")
        if not li_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="LinkedIn authentication failed. Could not obtain access token.",
            )

        # Return the access token
        return {
            "access_token": li_at,
            "premium_token": self.session.cookies.get("li_a", ""),
        }

    def authenticate_with_cookies(self, access_token, premium_token=None):
        """Authenticate with LinkedIn using cookies"""
        # Set cookies
        self.session.cookies.set("li_at", access_token, domain=".linkedin.com")

        if premium_token:
            self.session.cookies.set("li_a", premium_token, domain=".linkedin.com")

        # Verify authentication by making a test API call
        res = self.session.get(f"{self.BASE_URL}/me")

        if res.status_code != 200:
            logger.error(
                f"LinkedIn cookie authentication failed: {res.status_code} - {res.text}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="LinkedIn authentication failed. Invalid access token.",
            )

        return True


@router.post(
    "/accounts",
    response_model=Union[LinkedInAuthResponse, LinkedInCheckpointResponse],
    status_code=status.HTTP_201_CREATED,
)
async def connect_linkedin_account(
    auth_data: Union[LinkedInBasicAuth, LinkedInCookieAuth],
    current_user: CurrentUser,
    session: SessionDep,
):
    """Connect a LinkedIn account using either username/password or cookies"""
    client = LinkedInClient()

    auth_result = {}

    if isinstance(auth_data, LinkedInBasicAuth):
        # Username/password authentication
        auth_result = client.authenticate_with_credentials(
            auth_data.username, auth_data.password
        )
        # Check if authentication resulted in a challenge
        if auth_result and auth_result.get("status") == "CHALLENGE":
            account_id = str(uuid.uuid4())

            # Return a checkpoint response with status code 202
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content=LinkedInCheckpointResponse(
                    object="Checkpoint",
                    account_id=account_id,
                    checkpoint={
                        "type": auth_result.get("challenge_type", "UNKNOWN"),
                        "url": auth_result.get("challenge_url", ""),
                    },
                ).dict(),
            )

    elif isinstance(auth_data, LinkedInCookieAuth):
        # Cookie authentication
        client.authenticate_with_cookies(
            auth_data.access_token, auth_data.premium_token
        )
        auth_result = {
            "access_token": auth_data.access_token,
            "premium_token": auth_data.premium_token,
        }

    # If we reached here, authentication was successful
    account_id = str(uuid.uuid4())

    return LinkedInAuthResponse(object="AccountCreated", account_id=account_id)


@router.post(
    "/accounts/checkpoint",
    response_model=Union[LinkedInAuthResponse, LinkedInCheckpointResponse],
    status_code=status.HTTP_200_OK,
)
async def solve_linkedin_checkpoint(
    checkpoint_data: LinkedInCheckpointSolveRequest,
    current_user: CurrentUser,
    session: SessionDep,
):
    """Solve a LinkedIn authentication challenge (2FA, OTP, etc.)"""
    # In a real implementation, you would:
    # 1. Retrieve the pending authentication intent from storage using account_id
    # 2. Submit the code to LinkedIn to verify the challenge
    # 3. Return success or another challenge if needed

    # For demo purposes, we'll simulate a successful verification after a brief delay
    # This would normally interact with LinkedIn's verification endpoints

    # Simulate processing time
    time.sleep(0.5)

    # 10% chance of returning another challenge (for demo purposes)
    import random

    if random.random() < 0.1:
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content=LinkedInCheckpointResponse(
                object="Checkpoint",
                account_id=checkpoint_data.account_id,
                checkpoint={
                    "type": "OTP",  # A different challenge
                    "message": "Please enter the OTP sent to your email",
                },
            ).dict(),
        )

    # 90% chance of successful verification
    return LinkedInAuthResponse(
        object="AccountCreated", account_id=checkpoint_data.account_id
    )


@router.get("/accounts/{account_id}", response_model=LinkedInAccountResponse)
async def get_linkedin_account(
    account_id: str, current_user: CurrentUser, session: SessionDep
):
    """Retrieve a LinkedIn account by its ID"""
    # In a real implementation, you would:
    # 1. Fetch the account from the database
    # 2. Verify that it belongs to the current user
    # 3. Return the account details

    # For now, return a mock response
    return LinkedInAccountResponse(
        object="Account",
        type="LINKEDIN",
        id=account_id,
        name=f"LinkedIn Account for {current_user.email}",
        created_at=datetime.utcnow(),
        connection_params={
            "linkedin": {
                "username": "user@example.com"  # Would be fetched from DB in real implementation
            }
        },
        sources=[{"id": "linkedin_primary", "status": "OK"}],
        groups=[],
    )
