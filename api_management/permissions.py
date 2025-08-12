import logging
from typing import Any

from django.utils import timezone
from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.views import View

from billing.models import Subscription

logger = logging.getLogger(__name__)


class IsPaidUser(permissions.BasePermission):
    """
    Custom permission to only allow users with active paid subscriptions.
    """
    
    message = "Active paid subscription required to access this resource."
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Check if user has an active paid subscription.
        """
        if not request.user or not request.user.is_authenticated:
            return False
            
        return self.has_active_paid_subscription(request.user)
    
    def has_active_paid_subscription(self, user) -> bool:
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
                logger.warning(f"User {user.email} subscription expired")
                return False
                
            # For trial subscriptions, ensure they haven't exceeded trial period
            if subscription.status == 'trialing':
                if subscription.trial_end and subscription.trial_end < timezone.now():
                    logger.warning(f"User {user.email} trial period expired")
                    return False
                    
            return True
            
        except Subscription.DoesNotExist:
            logger.warning(f"User {user.email} has no active subscription")
            return False


class HasValidAPIKey(permissions.BasePermission):
    """
    Custom permission to check if request has a valid API key.
    """
    
    message = "Valid API key required to access this resource."
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Check if request has a valid API key in the authentication.
        """
        # Check if user was authenticated via API key
        if hasattr(request, 'auth') and hasattr(request.auth, 'key_id'):
            return True
            
        return False


class HasSufficientCredits(permissions.BasePermission):
    """
    Custom permission to check if user has sufficient credits for API usage.
    """
    
    message = "Insufficient credits to access this resource."
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Check if user has sufficient credits.
        This is a basic check - actual credit deduction should happen in the view.
        """
        if not request.user or not request.user.is_authenticated:
            return False
            
        # Import here to avoid circular imports
        from api_management.models import UserCredits
        
        try:
            user_credits = UserCredits.objects.get(user=request.user)
            # Check if user has at least 1 credit
            return user_credits.balance > 0
        except UserCredits.DoesNotExist:
            return False


class IsAPIKeyOwner(permissions.BasePermission):
    """
    Custom permission to check if user owns the API key being accessed.
    """
    
    message = "You can only access your own API keys."
    
    def has_object_permission(self, request: Request, view: View, obj: Any) -> bool:
        """
        Check if the user owns the API key object.
        """
        return obj.user == request.user


class IsSubscriptionOwner(permissions.BasePermission):
    """
    Custom permission to check if user owns the subscription being accessed.
    """
    
    message = "You can only access your own subscription."
    
    def has_object_permission(self, request: Request, view: View, obj: Any) -> bool:
        """
        Check if the user owns the subscription object.
        """
        return obj.user == request.user


class RateLimitPermission(permissions.BasePermission):
    """
    Custom permission to enforce rate limiting based on API key limits.
    """
    
    message = "Rate limit exceeded for this API key."
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Check if the request is within rate limits.
        """
        if not hasattr(request, 'auth') or not hasattr(request.auth, 'key_id'):
            return True  # Skip rate limiting if no API key
            
        # Import here to avoid circular imports
        from api_management.models import RateLimitTracker
        from django.utils import timezone
        from datetime import timedelta
        
        api_key = request.auth
        now = timezone.now()
        
        # Check minute limit
        minute_ago = now - timedelta(minutes=1)
        minute_requests = RateLimitTracker.objects.filter(
            api_key=api_key,
            created_at__gte=minute_ago
        ).count()
        
        if minute_requests >= api_key.rate_limit_per_minute:
            logger.warning(
                f"Rate limit exceeded for API key {api_key.name}: "
                f"{minute_requests} requests in last minute"
            )
            return False
            
        # Check hour limit
        hour_ago = now - timedelta(hours=1)
        hour_requests = RateLimitTracker.objects.filter(
            api_key=api_key,
            created_at__gte=hour_ago
        ).count()
        
        if hour_requests >= api_key.rate_limit_per_hour:
            logger.warning(
                f"Rate limit exceeded for API key {api_key.name}: "
                f"{hour_requests} requests in last hour"
            )
            return False
            
        # Check day limit
        day_ago = now - timedelta(days=1)
        day_requests = RateLimitTracker.objects.filter(
            api_key=api_key,
            created_at__gte=day_ago
        ).count()
        
        if day_requests >= api_key.rate_limit_per_day:
            logger.warning(
                f"Rate limit exceeded for API key {api_key.name}: "
                f"{day_requests} requests in last day"
            )
            return False
            
        return True