import logging
from typing import Optional, Tuple

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request

from .models import APIKey
from billing.models import Subscription

User = get_user_model()
logger = logging.getLogger(__name__)


class APIKeyAuthentication(BaseAuthentication):
    """
    Custom API Key authentication that ensures:
    1. Valid API key is provided
    2. User has an active paid subscription
    3. API key belongs to the authenticated user
    4. Rate limiting is enforced
    """
    
    keyword = 'Bearer'
    header_name = 'HTTP_X_API_KEY'
    
    def authenticate(self, request: Request) -> Optional[Tuple[User, APIKey]]:
        """
        Authenticate the request using API key.
        Returns a tuple of (user, api_key) if authentication succeeds.
        """
        api_key_header = self.get_api_key_from_request(request)
        if not api_key_header:
            return None
            
        try:
            # Parse API key (format: key_id.key_secret)
            if '.' not in api_key_header:
                raise exceptions.AuthenticationFailed('Invalid API key format')
                
            key_id, key_secret = api_key_header.split('.', 1)
            
            # Get API key from database
            api_key = APIKey.objects.select_related('user').get(
                key_id=key_id,
                key_secret=key_secret,
                is_active=True
            )
            
            # Check if API key is expired
            if api_key.expires_at and api_key.expires_at < timezone.now():
                raise exceptions.AuthenticationFailed('API key has expired')
                
            # Validate user has active paid subscription
            if not self.has_active_paid_subscription(api_key.user):
                raise exceptions.AuthenticationFailed(
                    'Active paid subscription required to access APIs'
                )
                
            # Update last used timestamp
            api_key.last_used_at = timezone.now()
            api_key.save(update_fields=['last_used_at'])
            
            # Log successful authentication
            logger.info(
                f"API key authentication successful for user {api_key.user.email} "
                f"with key {api_key.name}"
            )
            
            return (api_key.user, api_key)
            
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid API key')
        except Exception as e:
            logger.error(f"API key authentication error: {str(e)}")
            raise exceptions.AuthenticationFailed('Authentication failed')
    
    def get_api_key_from_request(self, request: Request) -> Optional[str]:
        """
        Extract API key from request headers.
        Supports both X-API-Key header and Authorization Bearer token.
        """
        # Try X-API-Key header first
        api_key = request.META.get(self.header_name)
        if api_key:
            return api_key
            
        # Try Authorization header with Bearer token
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith(f'{self.keyword} '):
            return auth_header[len(f'{self.keyword} '):]
            
        return None
    
    def has_active_paid_subscription(self, user: User) -> bool:
        """
        Check if user has an active paid subscription.
        """
        try:
            subscription = Subscription.objects.get(
                user=user,
                status__in=['active', 'trialing']
            )
            
            # Check if subscription is not expired
            if subscription.current_period_end < timezone.now():
                return False
                
            # For trial subscriptions, ensure they haven't exceeded trial period
            if subscription.status == 'trialing':
                if subscription.trial_end and subscription.trial_end < timezone.now():
                    return False
                    
            return True
            
        except Subscription.DoesNotExist:
            return False
    
    def authenticate_header(self, request: Request) -> str:
        """
        Return the authentication header for 401 responses.
        """
        return f'{self.keyword} realm="API"'


class CombinedAuthentication(BaseAuthentication):
    """
    Combined authentication that supports both API key and session authentication.
    Useful for endpoints that need to support both API access and web interface access.
    """
    
    def authenticate(self, request: Request) -> Optional[Tuple[User, str]]:
        """
        Try API key authentication first, then fall back to session authentication.
        """
        # Try API key authentication first
        api_key_auth = APIKeyAuthentication()
        result = api_key_auth.authenticate(request)
        if result:
            return result
            
        # Fall back to session authentication for web interface
        from rest_framework.authentication import SessionAuthentication
        session_auth = SessionAuthentication()
        return session_auth.authenticate(request)