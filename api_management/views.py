from datetime import datetime, timedelta

import stripe
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import APIKeyAuthentication, CombinedAuthentication
from .permissions import (
    IsPaidUser, 
    HasValidAPIKey, 
    HasSufficientCredits, 
    IsAPIKeyOwner, 
    RateLimitPermission
)

from django.conf import settings
from django.db.models import Avg, Count, Q, Sum
from django.utils import timezone

from .base_views import (
    BaseAPIView,
    BaseListCreateAPIView,
    BaseRetrieveUpdateDestroyAPIView,
    BaseListAPIView,
    BaseCreateAPIView,
    BaseRetrieveAPIView
)
from .response_utils import APIResponse, PaginationHelper
from .response_serializers import (
    StandardResponseSerializer,
    ErrorResponseSerializer,
    PaginatedResponseSerializer,
    ValidationErrorResponseSerializer
)

from .models import (
    APIKey,
    APIUsage,
    APIUsageAnalytics,
    CreditPackage,
    PaymentMethod,
    RateLimitTracker,
    ReferralProgram,
    UserCredits,
)
from .serializers import (
    APIKeyCreateSerializer,
    APIKeySerializer,
    APIKeyStatsSerializer,
    APIUsageAnalyticsSerializer,
    APIUsageSerializer,
    CreditPackageSerializer,
    CreditPurchaseSerializer,
    LocationBasedPaymentSerializer,
    PaymentMethodSerializer,
    RateLimitTrackerSerializer,
    ReferralCreateSerializer,
    ReferralProgramSerializer,
    ReferralStatsSerializer,
    UsageTrackingSerializer,
    UserCreditsSerializer,
    UserStatsSerializer,
)

# Configure Stripe
stripe.api_key = settings.STRIPE_SECRET_KEY


class APIKeyListCreateView(BaseListCreateAPIView):
    """API Key list and create endpoint"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    def get_serializer_class(self):
        if self.request.method == "POST":
            return APIKeyCreateSerializer
        return APIKeySerializer

    @extend_schema(
        summary="List API keys",
        description="Get all API keys for the authenticated user",
        responses={200: PaginatedResponseSerializer},
        tags=["API Management"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Create API key",
        description="Create a new API key for the authenticated user",
        request=APIKeyCreateSerializer,
        responses={
            201: StandardResponseSerializer,
            400: ValidationErrorResponseSerializer
        },
        tags=["API Management"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def get_queryset(self):
        return APIKey.objects.filter(user=self.request.user).order_by("-created_at")


class APIKeyDetailView(BaseRetrieveUpdateDestroyAPIView):
    """API Key detail, update and delete endpoint"""

    serializer_class = APIKeySerializer
    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser, IsAPIKeyOwner]

    @extend_schema(
        summary="Get API key details",
        description="Retrieve details of a specific API key",
        responses={
            200: StandardResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["API Management"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Update API key", 
        description="Update a specific API key",
        responses={
            200: StandardResponseSerializer,
            400: ValidationErrorResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["API Management"]
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @extend_schema(
        summary="Partially update API key",
        description="Partially update a specific API key",
        responses={
            200: StandardResponseSerializer,
            400: ValidationErrorResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["API Management"],
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    @extend_schema(
        summary="Delete API key", 
        description="Delete a specific API key",
        responses={
            204: StandardResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["API Management"]
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)

    def get_queryset(self):
        return APIKey.objects.filter(user=self.request.user)


class APIKeyRegenerateView(BaseAPIView):
    """API Key regeneration endpoint"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser, IsAPIKeyOwner]

    @extend_schema(
        summary="Regenerate API key",
        description="Regenerate secret for an existing API key",
        responses={
            200: StandardResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["API Management"],
    )
    def post(self, request, pk):
        try:
            api_key = APIKey.objects.get(pk=pk, user=request.user)

            # Generate new secret
            import secrets

            new_secret = secrets.token_urlsafe(48)
            api_key.key_secret = new_secret
            api_key.save()

            return APIResponse.success(
                data={
                    "key_id": api_key.key_id,
                    "key_secret": api_key.key_secret,
                    "full_key": f"{api_key.key_id}.{api_key.key_secret}",
                },
                message="API key regenerated successfully",
                request_id=request.request_id
            )

        except APIKey.DoesNotExist:
            return APIResponse.not_found(
                message="API key not found",
                request_id=request.request_id
            )


class APIKeyStatsView(BaseAPIView):
    """API Key statistics endpoint"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser, IsAPIKeyOwner]

    @extend_schema(
        summary="Get API key statistics",
        description="Get usage statistics for a specific API key",
        responses={
            200: StandardResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["Analytics & Reports"],
    )
    def get(self, request, pk):
        try:
            api_key = APIKey.objects.get(pk=pk, user=request.user)

            # Calculate date ranges
            today = timezone.now().date()
            month_start = today.replace(day=1)

            # Get usage statistics
            usage_queryset = APIUsage.objects.filter(api_key=api_key)

            total_requests = usage_queryset.count()
            requests_today = usage_queryset.filter(created_at__date=today).count()
            requests_this_month = usage_queryset.filter(
                created_at__date__gte=month_start
            ).count()

            credits_used_today = (
                usage_queryset.filter(created_at__date=today).aggregate(
                    total=Sum("credits_used")
                )["total"]
                or 0
            )

            credits_used_this_month = (
                usage_queryset.filter(created_at__date__gte=month_start).aggregate(
                    total=Sum("credits_used")
                )["total"]
                or 0
            )

            # Most used endpoint
            most_used = (
                usage_queryset.values("endpoint")
                .annotate(count=Count("endpoint"))
                .order_by("-count")
                .first()
            )
            most_used_endpoint = most_used["endpoint"] if most_used else "N/A"

            # Average response time
            avg_response_time = (
                usage_queryset.aggregate(avg=Avg("response_time_ms"))["avg"] or 0
            )

            # Success rate
            total_requests_count = usage_queryset.count()
            successful_requests = usage_queryset.filter(status_code__lt=400).count()
            success_rate = (
                (successful_requests / total_requests_count * 100)
                if total_requests_count > 0
                else 0
            )

            stats = {
                "total_requests": total_requests,
                "requests_today": requests_today,
                "requests_this_month": requests_this_month,
                "credits_used_today": credits_used_today,
                "credits_used_this_month": credits_used_this_month,
                "most_used_endpoint": most_used_endpoint,
                "average_response_time": round(avg_response_time, 2),
                "success_rate": round(success_rate, 2),
                "last_used": api_key.last_used_at,
            }

            serializer = APIKeyStatsSerializer(stats)
            return APIResponse.success(serializer.data)

        except APIKey.DoesNotExist:
            return APIResponse.not_found("API key not found")


class APIUsageListView(BaseListAPIView):
    """API Usage list endpoint"""

    serializer_class = APIUsageSerializer
    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="List API usage",
        description="Get API usage history for the authenticated user",
        responses={200: PaginatedResponseSerializer},
        tags=["Analytics & Reports"],
        parameters=[
            OpenApiParameter(
                name="api_key",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="Filter by API key ID",
            ),
            OpenApiParameter(
                name="service",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filter by service name",
            ),
            OpenApiParameter(
                name="status_code",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="Filter by HTTP status code",
            ),
            OpenApiParameter(
                name="date_from",
                type=OpenApiTypes.DATE,
                location=OpenApiParameter.QUERY,
                description="Filter from date (YYYY-MM-DD)",
            ),
            OpenApiParameter(
                name="date_to",
                type=OpenApiTypes.DATE,
                location=OpenApiParameter.QUERY,
                description="Filter to date (YYYY-MM-DD)",
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        queryset = (
            APIUsage.objects.filter(user=self.request.user)
            .select_related("api_key", "service")
            .order_by("-created_at")
        )

        # Apply filters
        api_key_id = self.request.query_params.get("api_key")
        if api_key_id:
            queryset = queryset.filter(api_key_id=api_key_id)

        service = self.request.query_params.get("service")
        if service:
            queryset = queryset.filter(service__name__icontains=service)

        status_code = self.request.query_params.get("status_code")
        if status_code:
            queryset = queryset.filter(status_code=status_code)

        date_from = self.request.query_params.get("date_from")
        if date_from:
            try:
                date_from = datetime.strptime(date_from, "%Y-%m-%d").date()
                queryset = queryset.filter(created_at__date__gte=date_from)
            except ValueError:
                pass

        date_to = self.request.query_params.get("date_to")
        if date_to:
            try:
                date_to = datetime.strptime(date_to, "%Y-%m-%d").date()
                queryset = queryset.filter(created_at__date__lte=date_to)
            except ValueError:
                pass

        return queryset


class UserCreditsView(BaseRetrieveAPIView):
    """User credits endpoint"""

    serializer_class = UserCreditsSerializer
    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="Get user credits", 
        description="Get current user's credit information",
        responses={200: StandardResponseSerializer},
        tags=["Credits & Usage"]
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        credits, created = UserCredits.objects.get_or_create(user=self.request.user)
        return credits


class CreditPackageListView(BaseListAPIView):
    """Credit package list endpoint"""

    serializer_class = CreditPackageSerializer
    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="List credit packages",
        description="Get available credit packages for purchase",
        responses={200: PaginatedResponseSerializer},
        tags=["Credits & Usage"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return CreditPackage.objects.filter(is_active=True).order_by(
            "sort_order", "price"
        )


class CreditPurchaseView(BaseAPIView):
    """Credit purchase endpoint"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser, HasSufficientCredits]

    @extend_schema(
        summary="Purchase credits",
        description="Purchase credits using Stripe payment",
        request=CreditPurchaseSerializer,
        responses={
            200: StandardResponseSerializer,
            400: ValidationErrorResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["Credits & Usage"],
    )
    def post(self, request):
        serializer = CreditPurchaseSerializer(data=request.data)

        if serializer.is_valid():
            package_id = serializer.validated_data["package_id"]
            payment_method_id = serializer.validated_data.get("payment_method_id")

            try:
                # Get credit package
                package = CreditPackage.objects.get(id=package_id, is_active=True)

                # Create Stripe payment intent
                intent = stripe.PaymentIntent.create(
                    amount=int(package.price * 100),  # Convert to cents
                    currency=package.currency.lower(),
                    payment_method=payment_method_id,
                    confirmation_method="manual",
                    confirm=True,
                    metadata={
                        "user_id": request.user.id,
                        "package_id": package.id,
                        "credits": package.credits,
                    },
                )

                if intent.status == "succeeded":
                    # Add credits to user account
                    user_credits, created = UserCredits.objects.get_or_create(
                        user=request.user
                    )
                    user_credits.available_credits += package.credits
                    user_credits.total_purchased += package.credits
                    user_credits.save()

                    return APIResponse.success(
                        data={
                            "message": "Credits purchased successfully",
                            "credits_added": package.credits,
                            "total_credits": user_credits.available_credits,
                        },
                        request=request
                    )
                else:
                    return APIResponse.error(
                        message="Payment failed",
                        details=intent.status,
                        request=request
                    )

            except CreditPackage.DoesNotExist:
                return APIResponse.not_found(
                    message="Credit package not found",
                    request=request
                )

            except stripe.error.StripeError as e:
                return APIResponse.error(
                    message="Payment processing failed",
                    details=str(e),
                    request=request
                )

        return APIResponse.validation_error(
            errors=serializer.errors,
            request=request
        )


class UserStatsView(BaseAPIView):
    """User statistics endpoint"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="Get user statistics",
        description="Get comprehensive usage statistics for the authenticated user",
        responses={200: StandardResponseSerializer},
        tags=["Analytics & Reports"],
    )
    def get(self, request):
        user = request.user

        # Calculate date ranges
        today = timezone.now().date()
        month_start = today.replace(day=1)

        # API Key statistics
        api_keys = APIKey.objects.filter(user=user)
        total_api_keys = api_keys.count()
        active_api_keys = api_keys.filter(is_active=True).count()

        # Usage statistics
        usage_queryset = APIUsage.objects.filter(user=user)
        total_requests = usage_queryset.count()
        requests_today = usage_queryset.filter(created_at__date=today).count()
        requests_this_month = usage_queryset.filter(
            created_at__date__gte=month_start
        ).count()

        # Credits statistics
        user_credits = UserCredits.objects.filter(user=user).first()
        available_credits = user_credits.available_credits if user_credits else 0

        credits_used_today = (
            usage_queryset.filter(created_at__date=today).aggregate(
                total=Sum("credits_used")
            )["total"]
            or 0
        )

        credits_used_this_month = (
            usage_queryset.filter(created_at__date__gte=month_start).aggregate(
                total=Sum("credits_used")
            )["total"]
            or 0
        )

        # Most used service
        most_used = (
            usage_queryset.values("service__name")
            .annotate(count=Count("service__name"))
            .order_by("-count")
            .first()
        )
        most_used_service = most_used["service__name"] if most_used else "N/A"

        # Average response time
        avg_response_time = (
            usage_queryset.aggregate(avg=Avg("response_time_ms"))["avg"] or 0
        )

        # Success rate
        successful_requests = usage_queryset.filter(status_code__lt=400).count()
        success_rate = (
            (successful_requests / total_requests * 100) if total_requests > 0 else 0
        )

        stats = {
            "total_api_keys": total_api_keys,
            "active_api_keys": active_api_keys,
            "total_requests": total_requests,
            "requests_today": requests_today,
            "requests_this_month": requests_this_month,
            "available_credits": available_credits,
            "credits_used_today": credits_used_today,
            "credits_used_this_month": credits_used_this_month,
            "most_used_service": most_used_service,
            "average_response_time": round(avg_response_time, 2),
            "success_rate": round(success_rate, 2),
        }

        return APIResponse.success(
            data=stats,
            request=request
        )


class RateLimitStatusView(BaseAPIView):
    """Rate limit status endpoint"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="Get rate limit status",
        description="Get current rate limit status for user's API keys",
        parameters=[
            OpenApiParameter(
                name="api_key_id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="Filter by specific API key ID",
            ),
        ],
        responses={
            200: StandardResponseSerializer,
            404: ErrorResponseSerializer
        },
        tags=["Analytics & Reports"],
    )
    def get(self, request):
        api_key_id = request.query_params.get("api_key_id")

        if api_key_id:
            try:
                api_key = APIKey.objects.get(id=api_key_id, user=request.user)
                rate_limits = RateLimitTracker.objects.filter(api_key=api_key)
            except APIKey.DoesNotExist:
                return APIResponse.not_found("API key not found")
        else:
            rate_limits = RateLimitTracker.objects.filter(
                user=request.user
            ).select_related("api_key")

        serializer = RateLimitTrackerSerializer(rate_limits, many=True)
        return APIResponse.success(serializer.data)


class ReferralProgramListView(BaseListAPIView):
    """List user's referral programs"""

    serializer_class = ReferralProgramSerializer
    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="List referrals",
        description="Get all referrals for the authenticated user",
        responses={200: PaginatedResponseSerializer},
        tags=["Referrals"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return ReferralProgram.objects.filter(referrer=self.request.user)


class ReferralCreateView(BaseAPIView):
    """Create a referral using referral code"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="Use referral code",
        description="Apply a referral code to get bonus credits",
        request=ReferralCreateSerializer,
        responses={
            200: StandardResponseSerializer,
            400: ValidationErrorResponseSerializer
        },
        tags=["Referrals"],
    )
    def post(self, request):
        serializer = ReferralCreateSerializer(data=request.data)
        if serializer.is_valid():
            referral_code = serializer.validated_data["referral_code"]
            
            try:
                referral = ReferralProgram.objects.get(
                    referral_code=referral_code, status="pending"
                )
                
                # Check if user is trying to use their own referral code
                if referral.referrer == request.user:
                    return APIResponse.error(
                        message="Cannot use your own referral code",
                        request=request
                    )
                
                # Check if user already used a referral code
                if ReferralProgram.objects.filter(
                    referred_user=request.user, status="completed"
                ).exists():
                    return APIResponse.error(
                        message="You have already used a referral code",
                        request=request
                    )
                
                # Update referral
                referral.referred_user = request.user
                referral.status = "completed"
                referral.bonus_awarded = True
                referral.bonus_awarded_at = timezone.now()
                referral.save()
                
                # Award credits to both users
                referred_credits, _ = UserCredits.objects.get_or_create(
                    user=request.user
                )
                referred_credits.balance += referral.referred_bonus_credits
                referred_credits.save()
                
                referrer_credits, _ = UserCredits.objects.get_or_create(
                    user=referral.referrer
                )
                referrer_credits.balance += referral.referrer_bonus_credits
                referrer_credits.save()
                
                return APIResponse.success(
                    data={
                        "message": "Referral code applied successfully!",
                        "bonus_credits": float(referral.referred_bonus_credits),
                        "referrer_bonus": float(referral.referrer_bonus_credits),
                    },
                    request=request
                )
                
            except ReferralProgram.DoesNotExist:
                return APIResponse.error(
                    message="Invalid or expired referral code",
                    request=request
                )
        
        return APIResponse.validation_error(
            errors=serializer.errors,
            request=request
        )


class ReferralStatsView(BaseAPIView):
    """Get referral statistics for user"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="Get referral stats",
        description="Get referral statistics for the authenticated user",
        responses={200: StandardResponseSerializer},
        tags=["Referrals"],
    )
    def get(self, request):
        user = request.user
        
        # Get or create user's referral program
        referral_program, created = ReferralProgram.objects.get_or_create(
            referrer=user,
            defaults={
                "referrer_bonus_credits": 100.0,
                "referred_bonus_credits": 50.0,
                "expires_at": timezone.now() + timedelta(days=365),
            }
        )
        
        # Calculate stats
        total_referrals = ReferralProgram.objects.filter(referrer=user).count()
        pending_referrals = ReferralProgram.objects.filter(
            referrer=user, status="pending"
        ).count()
        completed_referrals = ReferralProgram.objects.filter(
            referrer=user, status="completed"
        ).count()
        
        total_bonus = ReferralProgram.objects.filter(
            referrer=user, status="completed"
        ).aggregate(total=Sum("referrer_bonus_credits"))["total"] or 0
        
        referral_link = f"{settings.FRONTEND_URL}/signup?ref={referral_program.referral_code}"
        
        stats = {
            "total_referrals": total_referrals,
            "pending_referrals": pending_referrals,
            "completed_referrals": completed_referrals,
            "total_bonus_earned": total_bonus,
            "referral_code": referral_program.referral_code,
            "referral_link": referral_link,
        }
        
        serializer = ReferralStatsSerializer(stats)
        return APIResponse.success(serializer.data)


class LocationBasedPaymentView(BaseAPIView):
    """Get payment methods based on user location"""

    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="Get payment methods by location",
        description="Get available payment methods based on country/location",
        request=LocationBasedPaymentSerializer,
        responses={
            200: StandardResponseSerializer,
            400: ValidationErrorResponseSerializer
        },
        tags=["Credits & Usage"],
    )
    def post(self, request):
        serializer = LocationBasedPaymentSerializer(data=request.data)
        if serializer.is_valid():
            country_code = serializer.validated_data["country_code"]
            
            # Get payment methods for the country
            payment_methods = PaymentMethod.objects.filter(
                country_code=country_code, is_active=True
            ).order_by("-is_default", "provider")
            
            # If no specific methods found, get default methods
            if not payment_methods.exists():
                payment_methods = PaymentMethod.objects.filter(
                    is_default=True, is_active=True
                )
            
            serializer = PaymentMethodSerializer(payment_methods, many=True)
            return APIResponse.success(serializer.data)
        
        return APIResponse.validation_error(serializer.errors)


class APIUsageAnalyticsView(BaseListAPIView):
    """Get API usage analytics"""

    serializer_class = APIUsageAnalyticsSerializer
    authentication_classes = [CombinedAuthentication]
    permission_classes = [IsAuthenticated, IsPaidUser]

    @extend_schema(
        summary="Get usage analytics",
        description="Get aggregated API usage analytics",
        responses={200: PaginatedResponseSerializer},
        parameters=[
            OpenApiParameter(
                name="period",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Period type: daily, weekly, monthly",
            ),
            OpenApiParameter(
                name="date_from",
                type=OpenApiTypes.DATE,
                location=OpenApiParameter.QUERY,
                description="Start date (YYYY-MM-DD)",
            ),
            OpenApiParameter(
                name="date_to",
                type=OpenApiTypes.DATE,
                location=OpenApiParameter.QUERY,
                description="End date (YYYY-MM-DD)",
            ),
        ],
        tags=["Analytics & Reports"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        queryset = APIUsageAnalytics.objects.filter(user=self.request.user)
        
        period = self.request.query_params.get("period")
        if period:
            queryset = queryset.filter(period_type=period)
        
        date_from = self.request.query_params.get("date_from")
        if date_from:
            try:
                date_from = datetime.strptime(date_from, "%Y-%m-%d").date()
                queryset = queryset.filter(date__gte=date_from)
            except ValueError:
                pass
        
        date_to = self.request.query_params.get("date_to")
        if date_to:
            try:
                date_to = datetime.strptime(date_to, "%Y-%m-%d").date()
                queryset = queryset.filter(date__lte=date_to)
            except ValueError:
                pass
        
        return queryset.order_by("-date")


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPaidUser])
@extend_schema(
    summary="Track API usage",
    description="Track API usage for billing and analytics",
    request=UsageTrackingSerializer,
    responses={
        200: StandardResponseSerializer,
        400: ValidationErrorResponseSerializer,
        401: ErrorResponseSerializer
    },
    tags=["Analytics & Reports"],
)
def track_api_usage(request):
    """Track API usage for billing and analytics"""
    serializer = UsageTrackingSerializer(data=request.data)
    if serializer.is_valid():
        data = serializer.validated_data
        
        # Get user's API key (assuming it's passed in headers)
        api_key_header = request.META.get("HTTP_X_API_KEY")
        if not api_key_header:
            return APIResponse.validation_error({"api_key": ["API key required"]})
        
        try:
            api_key = APIKey.objects.get(key=api_key_header, user=request.user)
        except APIKey.DoesNotExist:
            return APIResponse.error("Invalid API key", status_code=401)
        
        # Create usage record
        APIUsage.objects.create(
            user=request.user,
            api_key=api_key,
            endpoint=data["endpoint"],
            method=data["method"],
            status_code=data["status_code"],
            response_time_ms=data["response_time_ms"],
            credits_used=data["credits_used"],
            request_size_bytes=data.get("request_size_bytes", 0),
            response_size_bytes=data.get("response_size_bytes", 0),
            error_message=data.get("error_message", ""),
        )
        
        # Deduct credits
        user_credits, _ = UserCredits.objects.get_or_create(user=request.user)
        user_credits.balance -= data["credits_used"]
        user_credits.total_used += data["credits_used"]
        user_credits.save()
        
        return APIResponse.success(
            message="Usage tracked successfully",
            data={"credits_remaining": float(user_credits.balance)}
        )
    
    return APIResponse.validation_error(serializer.errors)
