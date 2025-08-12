import secrets
import string

from rest_framework import serializers

from django.contrib.auth import get_user_model
from django.utils import timezone

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

User = get_user_model()


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer for API Key"""

    key_secret = serializers.CharField(read_only=True)
    key_id = serializers.CharField(read_only=True)
    user_email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = APIKey
        fields = (
            "id",
            "name",
            "key_id",
            "key_secret",
            "user_email",
            "is_active",
            "allowed_ips",
            "rate_limit_per_minute",
            "rate_limit_per_hour",
            "rate_limit_per_day",
            "total_requests",
            "last_used_at",
            "expires_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "key_id",
            "key_secret",
            "total_requests",
            "last_used_at",
            "created_at",
            "updated_at",
        )

    def validate_name(self, value):
        """Validate API key name uniqueness for user"""
        user = self.context["request"].user
        if APIKey.objects.filter(user=user, name=value).exists():
            if not self.instance or self.instance.name != value:
                raise serializers.ValidationError(
                    "You already have an API key with this name."
                )
        return value

    def validate_allowed_ips(self, value):
        """Validate IP addresses format"""
        if value:
            ips = [ip.strip() for ip in value.split(",")]
            for ip in ips:
                if ip and not self.is_valid_ip(ip):
                    raise serializers.ValidationError(
                        f"Invalid IP address format: {ip}"
                    )
        return value

    def is_valid_ip(self, ip):
        """Basic IP validation"""
        import re

        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return re.match(pattern, ip) is not None

    def create(self, validated_data):
        """Create new API key with generated credentials"""
        user = self.context["request"].user

        # Generate key ID and secret
        key_id = self.generate_key_id()
        key_secret = self.generate_key_secret()

        api_key = APIKey.objects.create(
            user=user, key_id=key_id, key_secret=key_secret, **validated_data
        )

        return api_key

    def generate_key_id(self):
        """Generate unique key ID"""
        while True:
            key_id = "gst_" + "".join(
                secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
            )
            if not APIKey.objects.filter(key_id=key_id).exists():
                return key_id

    def generate_key_secret(self):
        """Generate key secret"""
        return secrets.token_urlsafe(48)


class APIKeyCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating API Key (returns full key)"""

    key_secret = serializers.CharField(read_only=True)
    key_id = serializers.CharField(read_only=True)
    full_key = serializers.SerializerMethodField()

    class Meta:
        model = APIKey
        fields = (
            "id",
            "name",
            "key_id",
            "key_secret",
            "full_key",
            "is_active",
            "allowed_ips",
            "rate_limit_per_minute",
            "rate_limit_per_hour",
            "rate_limit_per_day",
            "expires_at",
            "created_at",
        )
        read_only_fields = ("id", "key_id", "key_secret", "full_key", "created_at")

    def get_full_key(self, obj):
        """Return full API key (only shown once during creation)"""
        return f"{obj.key_id}.{obj.key_secret}"

    def validate_name(self, value):
        """Validate API key name uniqueness for user"""
        user = self.context["request"].user
        if APIKey.objects.filter(user=user, name=value).exists():
            raise serializers.ValidationError(
                "You already have an API key with this name."
            )
        return value

    def create(self, validated_data):
        """Create new API key with generated credentials"""
        user = self.context["request"].user

        # Check API key limit based on subscription
        max_keys = (
            getattr(user.subscription_plan, "max_api_keys", 5)
            if user.subscription_plan
            else 5
        )
        current_keys = APIKey.objects.filter(user=user, is_active=True).count()

        if current_keys >= max_keys:
            raise serializers.ValidationError(
                f"You have reached the maximum number of API keys ({max_keys}) for your plan."
            )

        # Generate key ID and secret
        key_id = self.generate_key_id()
        key_secret = self.generate_key_secret()

        api_key = APIKey.objects.create(
            user=user, key_id=key_id, key_secret=key_secret, **validated_data
        )

        return api_key

    def generate_key_id(self):
        """Generate unique key ID"""
        while True:
            key_id = "gst_" + "".join(
                secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
            )
            if not APIKey.objects.filter(key_id=key_id).exists():
                return key_id

    def generate_key_secret(self):
        """Generate key secret"""
        return secrets.token_urlsafe(48)


class APIUsageSerializer(serializers.ModelSerializer):
    """Serializer for API Usage"""

    user_email = serializers.EmailField(source="user.email", read_only=True)
    api_key_name = serializers.CharField(source="api_key.name", read_only=True)
    service_name = serializers.CharField(source="service.name", read_only=True)

    class Meta:
        model = APIUsage
        fields = (
            "id",
            "user_email",
            "api_key_name",
            "service_name",
            "endpoint",
            "method",
            "status_code",
            "response_time_ms",
            "credits_used",
            "ip_address",
            "user_agent",
            "request_size_bytes",
            "response_size_bytes",
            "error_message",
            "created_at",
        )
        read_only_fields = ("id", "created_at")


class CreditPackageSerializer(serializers.ModelSerializer):
    """Serializer for Credit Package"""

    class Meta:
        model = CreditPackage
        fields = (
            "id",
            "name",
            "description",
            "credits",
            "price",
            "package_type",
            "stripe_product_id",
            "stripe_price_id",
            "is_active",
            "is_popular",
            "sort_order",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class UserCreditsSerializer(serializers.ModelSerializer):
    """Serializer for User Credits"""

    user_email = serializers.EmailField(source="user.email", read_only=True)
    total_credits = serializers.SerializerMethodField()

    class Meta:
        model = UserCredits
        fields = (
            "id",
            "user_email",
            "available_credits",
            "total_purchased",
            "total_used",
            "trial_credits_granted",
            "trial_credits_used",
            "total_credits",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "total_purchased",
            "total_used",
            "trial_credits_granted",
            "trial_credits_used",
            "total_credits",
            "created_at",
            "updated_at",
        )

    def get_total_credits(self, obj):
        """Calculate total credits (purchased + trial)"""
        return obj.available_credits + obj.total_used


class RateLimitTrackerSerializer(serializers.ModelSerializer):
    """Serializer for Rate Limit Tracker"""

    user_email = serializers.EmailField(source="user.email", read_only=True)
    api_key_name = serializers.CharField(source="api_key.name", read_only=True)

    class Meta:
        model = RateLimitTracker
        fields = (
            "id",
            "user_email",
            "api_key_name",
            "endpoint",
            "requests_per_minute",
            "requests_per_hour",
            "requests_per_day",
            "window_start",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class APIKeyStatsSerializer(serializers.Serializer):
    """Serializer for API Key statistics"""

    total_requests = serializers.IntegerField()
    requests_today = serializers.IntegerField()
    requests_this_month = serializers.IntegerField()
    credits_used_today = serializers.IntegerField()
    credits_used_this_month = serializers.IntegerField()
    most_used_endpoint = serializers.CharField()
    average_response_time = serializers.FloatField()
    success_rate = serializers.FloatField()
    last_used = serializers.DateTimeField()


class UserStatsSerializer(serializers.Serializer):
    """Serializer for User statistics"""

    total_api_keys = serializers.IntegerField()
    active_api_keys = serializers.IntegerField()
    total_requests = serializers.IntegerField()
    requests_today = serializers.IntegerField()
    requests_this_month = serializers.IntegerField()
    available_credits = serializers.IntegerField()
    credits_used_today = serializers.IntegerField()
    credits_used_this_month = serializers.IntegerField()
    most_used_service = serializers.CharField()
    average_response_time = serializers.FloatField()
    success_rate = serializers.FloatField()


class CreditPurchaseSerializer(serializers.Serializer):
    """Serializer for credit purchase"""

    package_id = serializers.IntegerField()
    payment_method_id = serializers.CharField(required=False)

    def validate_package_id(self, value):
        """Validate credit package exists and is active"""
        try:
            package = CreditPackage.objects.get(id=value, is_active=True)
        except CreditPackage.DoesNotExist:
            raise serializers.ValidationError("Invalid or inactive credit package.")
        return value


class ReferralProgramSerializer(serializers.ModelSerializer):
    """Serializer for Referral Program"""

    referrer_email = serializers.EmailField(source="referrer.email", read_only=True)
    referred_user_email = serializers.EmailField(source="referred_user.email", read_only=True)

    class Meta:
        model = ReferralProgram
        fields = (
            "id",
            "referrer_email",
            "referred_user_email",
            "referral_code",
            "status",
            "referrer_bonus_credits",
            "referred_bonus_credits",
            "bonus_awarded",
            "bonus_awarded_at",
            "created_at",
            "updated_at",
            "expires_at",
        )
        read_only_fields = (
            "id",
            "referral_code",
            "bonus_awarded",
            "bonus_awarded_at",
            "created_at",
            "updated_at",
        )


class ReferralCreateSerializer(serializers.Serializer):
    """Serializer for creating referrals"""

    referral_code = serializers.CharField(max_length=20)

    def validate_referral_code(self, value):
        """Validate referral code exists and is active"""
        try:
            referral = ReferralProgram.objects.get(
                referral_code=value, status="pending"
            )
            # Check if referral hasn't expired
            if referral.expires_at and referral.expires_at < timezone.now():
                raise serializers.ValidationError("Referral code has expired.")
        except ReferralProgram.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired referral code.")
        return value


class PaymentMethodSerializer(serializers.ModelSerializer):
    """Serializer for Payment Method"""

    class Meta:
        model = PaymentMethod
        fields = (
            "id",
            "country_code",
            "country_name",
            "provider",
            "currency",
            "currency_symbol",
            "is_active",
            "is_default",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class APIUsageAnalyticsSerializer(serializers.ModelSerializer):
    """Serializer for API Usage Analytics"""

    user_email = serializers.EmailField(source="user.email", read_only=True)
    success_rate = serializers.SerializerMethodField()
    avg_credits_per_request = serializers.SerializerMethodField()

    class Meta:
        model = APIUsageAnalytics
        fields = (
            "id",
            "user_email",
            "date",
            "period_type",
            "total_requests",
            "successful_requests",
            "failed_requests",
            "success_rate",
            "total_credits_used",
            "avg_credits_per_request",
            "avg_response_time_ms",
            "total_data_transferred_mb",
            "endpoint_usage",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    def get_success_rate(self, obj):
        """Calculate success rate percentage"""
        if obj.total_requests == 0:
            return 0.0
        return round((obj.successful_requests / obj.total_requests) * 100, 2)

    def get_avg_credits_per_request(self, obj):
        """Calculate average credits per request"""
        if obj.total_requests == 0:
            return 0.0
        return round(float(obj.total_credits_used) / obj.total_requests, 4)


class LocationBasedPaymentSerializer(serializers.Serializer):
    """Serializer for getting payment methods based on location"""

    country_code = serializers.CharField(max_length=2)
    ip_address = serializers.IPAddressField(required=False)

    def validate_country_code(self, value):
        """Validate country code format"""
        if len(value) != 2:
            raise serializers.ValidationError("Country code must be 2 characters.")
        return value.upper()


class ReferralStatsSerializer(serializers.Serializer):
    """Serializer for referral statistics"""

    total_referrals = serializers.IntegerField()
    pending_referrals = serializers.IntegerField()
    completed_referrals = serializers.IntegerField()
    total_bonus_earned = serializers.DecimalField(max_digits=10, decimal_places=4)
    referral_code = serializers.CharField()
    referral_link = serializers.URLField()


class UsageTrackingSerializer(serializers.Serializer):
    """Serializer for tracking API usage"""

    endpoint = serializers.CharField()
    method = serializers.CharField()
    status_code = serializers.IntegerField()
    response_time_ms = serializers.IntegerField()
    credits_used = serializers.DecimalField(max_digits=10, decimal_places=4)
    request_size_bytes = serializers.IntegerField(default=0)
    response_size_bytes = serializers.IntegerField(default=0)
    error_message = serializers.CharField(required=False, allow_blank=True)
