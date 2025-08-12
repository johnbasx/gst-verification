import secrets
import string
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class APIKey(models.Model):
    """API Key model for authentication and access control"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_keys"
    )

    # API Key details
    name = models.CharField(
        max_length=100, help_text="Descriptive name for the API key"
    )
    key_id = models.CharField(max_length=20, unique=True, editable=False)
    key_secret = models.CharField(max_length=64, editable=False)

    # Permissions and restrictions
    is_active = models.BooleanField(default=True)
    allowed_ips = models.TextField(
        blank=True,
        help_text="Comma-separated list of allowed IP addresses. Leave empty for no restrictions.",
    )

    # Rate limiting
    rate_limit_per_minute = models.IntegerField(default=60)
    rate_limit_per_hour = models.IntegerField(default=1000)
    rate_limit_per_day = models.IntegerField(default=10000)

    # Usage tracking
    total_requests = models.BigIntegerField(default=0)
    last_used_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "api_keys"
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} - {self.name}"

    def save(self, *args, **kwargs):
        if not self.key_id:
            self.key_id = self.generate_key_id()
        if not self.key_secret:
            self.key_secret = self.generate_key_secret()
        super().save(*args, **kwargs)

    @staticmethod
    def generate_key_id():
        """Generate a unique key ID"""
        return "gst_" + "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
        )

    @staticmethod
    def generate_key_secret():
        """Generate a secure key secret"""
        return secrets.token_urlsafe(48)

    @property
    def is_expired(self):
        """Check if the API key is expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False

    @property
    def is_valid(self):
        """Check if the API key is valid (active and not expired)"""
        return self.is_active and not self.is_expired

    def get_allowed_ips_list(self):
        """Get list of allowed IP addresses"""
        if self.allowed_ips:
            return [ip.strip() for ip in self.allowed_ips.split(",") if ip.strip()]
        return []

    def is_ip_allowed(self, ip_address):
        """Check if an IP address is allowed"""
        allowed_ips = self.get_allowed_ips_list()
        if not allowed_ips:  # No restrictions
            return True
        return ip_address in allowed_ips


class APIUsage(models.Model):
    """Track API usage for billing and analytics"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_usage"
    )
    api_key = models.ForeignKey(
        APIKey, on_delete=models.CASCADE, related_name="usage_records"
    )

    # Request details
    endpoint = models.CharField(max_length=100)
    method = models.CharField(max_length=10)
    status_code = models.IntegerField()

    # Timing and performance
    response_time_ms = models.IntegerField(help_text="Response time in milliseconds")

    # Request metadata
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)

    # Billing
    credits_used = models.DecimalField(max_digits=10, decimal_places=4, default=1.0000)

    # Additional data
    request_size_bytes = models.IntegerField(default=0)
    response_size_bytes = models.IntegerField(default=0)

    # Error tracking
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "api_usage"
        verbose_name = "API Usage"
        verbose_name_plural = "API Usage Records"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["api_key", "created_at"]),
            models.Index(fields=["endpoint", "created_at"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.endpoint} - {self.created_at}"


class CreditPackage(models.Model):
    """Define credit packages for API usage"""

    name = models.CharField(max_length=100)
    description = models.TextField()

    # Credit details
    credits = models.IntegerField(help_text="Number of API credits")
    price = models.DecimalField(
        max_digits=10, decimal_places=2, help_text="Price in USD"
    )

    # Package type
    package_type = models.CharField(
        max_length=20,
        choices=[
            ("one_time", "One Time"),
            ("monthly", "Monthly"),
            ("yearly", "Yearly"),
        ],
        default="one_time",
    )

    # Stripe product and price IDs
    stripe_product_id = models.CharField(max_length=100, blank=True)
    stripe_price_id = models.CharField(max_length=100, blank=True)

    # Status
    is_active = models.BooleanField(default=True)
    is_popular = models.BooleanField(default=False)

    # Display order
    sort_order = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "credit_packages"
        verbose_name = "Credit Package"
        verbose_name_plural = "Credit Packages"
        ordering = ["sort_order", "price"]

    def __str__(self):
        return f"{self.name} - {self.credits} credits - ${self.price}"

    @property
    def price_per_credit(self):
        """Calculate price per credit"""
        if self.credits > 0:
            return self.price / self.credits
        return 0


class UserCredits(models.Model):
    """Track user's available credits"""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="credits"
    )

    # Credit balance
    available_credits = models.DecimalField(
        max_digits=15, decimal_places=4, default=0.0000
    )
    total_purchased = models.DecimalField(
        max_digits=15, decimal_places=4, default=0.0000
    )
    total_used = models.DecimalField(max_digits=15, decimal_places=4, default=0.0000)

    # Free trial credits
    trial_credits_granted = models.DecimalField(
        max_digits=10, decimal_places=4, default=100.0000
    )
    trial_credits_used = models.DecimalField(
        max_digits=10, decimal_places=4, default=0.0000
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_credits"
        verbose_name = "User Credits"
        verbose_name_plural = "User Credits"

    def __str__(self):
        return f"{self.user.email} - {self.available_credits} credits"

    @property
    def trial_credits_remaining(self):
        """Calculate remaining trial credits"""
        return max(0, self.trial_credits_granted - self.trial_credits_used)

    @property
    def total_credits_remaining(self):
        """Calculate total remaining credits (trial + purchased)"""
        return self.available_credits + self.trial_credits_remaining

    def can_use_credits(self, amount):
        """Check if user has enough credits"""
        return self.total_credits_remaining >= amount

    def use_credits(self, amount):
        """Use credits (trial first, then purchased)"""
        if not self.can_use_credits(amount):
            raise ValueError("Insufficient credits")

        remaining_amount = amount

        # Use trial credits first
        trial_available = self.trial_credits_remaining
        if trial_available > 0 and remaining_amount > 0:
            trial_to_use = min(trial_available, remaining_amount)
            self.trial_credits_used += trial_to_use
            remaining_amount -= trial_to_use

        # Use purchased credits
        if remaining_amount > 0:
            self.available_credits -= remaining_amount
            self.total_used += remaining_amount

        self.save()

    def add_credits(self, amount):
        """Add purchased credits"""
        self.available_credits += amount
        self.total_purchased += amount
        self.save()


class RateLimitTracker(models.Model):
    """Track rate limiting for API keys"""

    api_key = models.ForeignKey(
        APIKey, on_delete=models.CASCADE, related_name="rate_limits"
    )

    # Time windows
    window_type = models.CharField(
        max_length=10,
        choices=[
            ("minute", "Per Minute"),
            ("hour", "Per Hour"),
            ("day", "Per Day"),
        ],
    )

    window_start = models.DateTimeField()
    request_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "rate_limit_tracker"
        verbose_name = "Rate Limit Tracker"
        verbose_name_plural = "Rate Limit Trackers"
        unique_together = ["api_key", "window_type", "window_start"]
        indexes = [
            models.Index(fields=["api_key", "window_type", "window_start"]),
        ]

    def __str__(self):
        return f"{self.api_key.name} - {self.window_type} - {self.window_start}"


class ReferralProgram(models.Model):
    """Referral program model for tracking user referrals"""

    referrer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="referrals_made"
    )
    referred_user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="referral_info"
    )

    # Referral details
    referral_code = models.CharField(max_length=20, unique=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("completed", "Completed"),
            ("expired", "Expired"),
        ],
        default="pending",
    )

    # Rewards
    referrer_bonus_credits = models.DecimalField(
        max_digits=10, decimal_places=4, default=50.0000
    )
    referred_bonus_credits = models.DecimalField(
        max_digits=10, decimal_places=4, default=25.0000
    )
    bonus_awarded = models.BooleanField(default=False)
    bonus_awarded_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "referral_programs"
        verbose_name = "Referral Program"
        verbose_name_plural = "Referral Programs"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.referrer.email} -> {self.referred_user.email}"

    @staticmethod
    def generate_referral_code():
        """Generate a unique referral code"""
        return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = self.generate_referral_code()
        super().save(*args, **kwargs)


class PaymentMethod(models.Model):
    """Payment method configuration based on user location"""

    country_code = models.CharField(max_length=2, help_text="ISO 3166-1 alpha-2 country code")
    country_name = models.CharField(max_length=100)
    
    # Payment provider configuration
    provider = models.CharField(
        max_length=20,
        choices=[
            ("stripe", "Stripe"),
            ("razorpay", "Razorpay"),
            ("paypal", "PayPal"),
        ],
    )
    
    # Provider-specific settings
    provider_config = models.JSONField(
        default=dict,
        help_text="Provider-specific configuration (API keys, webhook URLs, etc.)"
    )
    
    # Currency and pricing
    currency = models.CharField(max_length=3, help_text="ISO 4217 currency code")
    currency_symbol = models.CharField(max_length=5, default="$")
    
    # Status
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "payment_methods"
        verbose_name = "Payment Method"
        verbose_name_plural = "Payment Methods"
        ordering = ["country_name"]
        unique_together = ["country_code", "provider"]

    def __str__(self):
        return f"{self.country_name} - {self.provider.title()}"


class APIUsageAnalytics(models.Model):
    """Aggregated API usage analytics for reporting"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="usage_analytics"
    )
    
    # Time period
    date = models.DateField()
    period_type = models.CharField(
        max_length=10,
        choices=[
            ("daily", "Daily"),
            ("weekly", "Weekly"),
            ("monthly", "Monthly"),
        ],
        default="daily",
    )
    
    # Usage metrics
    total_requests = models.IntegerField(default=0)
    successful_requests = models.IntegerField(default=0)
    failed_requests = models.IntegerField(default=0)
    total_credits_used = models.DecimalField(max_digits=15, decimal_places=4, default=0.0000)
    
    # Performance metrics
    avg_response_time_ms = models.FloatField(default=0.0)
    total_data_transferred_mb = models.FloatField(default=0.0)
    
    # Endpoint breakdown (JSON field for flexibility)
    endpoint_usage = models.JSONField(
        default=dict,
        help_text="Breakdown of usage by endpoint"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "api_usage_analytics"
        verbose_name = "API Usage Analytics"
        verbose_name_plural = "API Usage Analytics"
        ordering = ["-date"]
        unique_together = ["user", "date", "period_type"]
        indexes = [
            models.Index(fields=["user", "date"]),
            models.Index(fields=["date", "period_type"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.date} ({self.period_type})"
