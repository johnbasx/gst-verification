import json
import uuid
from decimal import Decimal

from django.conf import settings
from django.db import models
from django.utils import timezone


class GSTService(models.Model):
    """Available GST services and their configurations"""

    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    description = models.TextField()

    # Service configuration
    endpoint_path = models.CharField(max_length=100, help_text="API endpoint path")
    credit_cost = models.DecimalField(
        max_digits=8, decimal_places=4, help_text="Credits consumed per request"
    )

    # Rate limiting (per service)
    rate_limit_per_minute = models.IntegerField(default=10)
    rate_limit_per_hour = models.IntegerField(default=100)
    rate_limit_per_day = models.IntegerField(default=1000)

    # Service status
    is_active = models.BooleanField(default=True)
    is_premium = models.BooleanField(
        default=False, help_text="Requires premium subscription"
    )

    # Documentation
    documentation_url = models.URLField(blank=True)
    example_request = models.JSONField(default=dict, blank=True)
    example_response = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "gst_services"
        verbose_name = "GST Service"
        verbose_name_plural = "GST Services"
        ordering = ["name"]

    def __str__(self):
        return self.name


class GSTRequest(models.Model):
    """GST API request logs"""

    # Request identification
    request_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    # User and API key
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="gst_requests"
    )
    api_key = models.ForeignKey(
        "api_management.APIKey", on_delete=models.CASCADE, related_name="gst_requests"
    )
    service = models.ForeignKey(
        GSTService, on_delete=models.CASCADE, related_name="requests"
    )

    # Request details
    method = models.CharField(max_length=10, default="POST")
    endpoint = models.CharField(max_length=200)

    # Request data
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.JSONField(default=dict, blank=True)
    request_params = models.JSONField(default=dict, blank=True)

    # Response data
    response_status_code = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.JSONField(default=dict, blank=True)

    # Performance metrics
    response_time_ms = models.IntegerField(
        null=True, blank=True, help_text="Response time in milliseconds"
    )

    # Billing and credits
    credits_consumed = models.DecimalField(
        max_digits=8, decimal_places=4, default=0.0000
    )
    billing_status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("charged", "Charged"),
            ("failed", "Failed"),
            ("refunded", "Refunded"),
        ],
        default="pending",
    )

    # Request metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Status and error handling
    status = models.CharField(
        max_length=20,
        choices=[
            ("success", "Success"),
            ("error", "Error"),
            ("rate_limited", "Rate Limited"),
            ("insufficient_credits", "Insufficient Credits"),
            ("invalid_request", "Invalid Request"),
        ],
        default="success",
    )

    error_message = models.TextField(blank=True)
    error_code = models.CharField(max_length=50, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "gst_requests"
        verbose_name = "GST Request"
        verbose_name_plural = "GST Requests"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["api_key", "-created_at"]),
            models.Index(fields=["service", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.service.name} - {self.user.email} - {self.created_at}"

    @property
    def is_successful(self):
        """Check if request was successful"""
        return (
            self.status == "success" and 200 <= (self.response_status_code or 0) < 300
        )

    @property
    def duration_seconds(self):
        """Get response time in seconds"""
        if self.response_time_ms:
            return self.response_time_ms / 1000.0
        return None


class GSTVerificationResult(models.Model):
    """Structured GST verification results"""

    request = models.OneToOneField(
        GSTRequest, on_delete=models.CASCADE, related_name="verification_result"
    )

    # GST details
    gstin = models.CharField(max_length=15, db_index=True)
    legal_name = models.CharField(max_length=255, blank=True)
    trade_name = models.CharField(max_length=255, blank=True)

    # Business details
    business_type = models.CharField(max_length=100, blank=True)
    constitution = models.CharField(max_length=100, blank=True)

    # Address information
    address = models.TextField(blank=True)
    state_code = models.CharField(max_length=2, blank=True)
    state_name = models.CharField(max_length=100, blank=True)
    pincode = models.CharField(max_length=10, blank=True)

    # Registration details
    registration_date = models.DateField(null=True, blank=True)
    cancellation_date = models.DateField(null=True, blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ("active", "Active"),
            ("cancelled", "Cancelled"),
            ("suspended", "Suspended"),
            ("invalid", "Invalid"),
        ],
        blank=True,
    )

    # Verification metadata
    is_verified = models.BooleanField(default=False)
    verification_confidence = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Confidence score (0-100)",
    )

    # Additional data
    additional_data = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "gst_verification_results"
        verbose_name = "GST Verification Result"
        verbose_name_plural = "GST Verification Results"
        indexes = [
            models.Index(fields=["gstin"]),
            models.Index(fields=["status"]),
            models.Index(fields=["is_verified"]),
        ]

    def __str__(self):
        return f"{self.gstin} - {self.legal_name or 'Unknown'}"

    @property
    def is_active_gst(self):
        """Check if GST is active"""
        return self.status == "active" and self.is_verified


class GSTCache(models.Model):
    """Cache for GST verification results to reduce API calls"""

    gstin = models.CharField(max_length=15, unique=True, db_index=True)

    # Cached data
    cached_data = models.JSONField()

    # Cache metadata
    cache_hit_count = models.IntegerField(default=0)
    last_verified_at = models.DateTimeField()

    # Cache validity
    expires_at = models.DateTimeField()
    is_valid = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "gst_cache"
        verbose_name = "GST Cache"
        verbose_name_plural = "GST Cache"
        indexes = [
            models.Index(fields=["gstin"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["is_valid"]),
        ]

    def __str__(self):
        return f"Cache: {self.gstin}"

    @property
    def is_expired(self):
        """Check if cache entry is expired"""
        return timezone.now() > self.expires_at

    def increment_hit_count(self):
        """Increment cache hit counter"""
        self.cache_hit_count += 1
        self.save(update_fields=["cache_hit_count"])

    def invalidate(self):
        """Invalidate cache entry"""
        self.is_valid = False
        self.save(update_fields=["is_valid"])


class GSTBulkRequest(models.Model):
    """Bulk GST verification requests"""

    # Request identification
    batch_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    # User and API key
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="bulk_gst_requests",
    )
    api_key = models.ForeignKey(
        "api_management.APIKey",
        on_delete=models.CASCADE,
        related_name="bulk_gst_requests",
    )

    # Batch details
    total_records = models.IntegerField()
    processed_records = models.IntegerField(default=0)
    successful_records = models.IntegerField(default=0)
    failed_records = models.IntegerField(default=0)

    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("processing", "Processing"),
            ("completed", "Completed"),
            ("failed", "Failed"),
            ("cancelled", "Cancelled"),
        ],
        default="pending",
    )

    # File handling
    input_file_name = models.CharField(max_length=255, blank=True)
    output_file_url = models.URLField(blank=True)

    # Billing
    total_credits_consumed = models.DecimalField(
        max_digits=10, decimal_places=4, default=0.0000
    )

    # Progress tracking
    progress_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, default=0.00
    )
    estimated_completion_time = models.DateTimeField(null=True, blank=True)

    # Timestamps
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "gst_bulk_requests"
        verbose_name = "GST Bulk Request"
        verbose_name_plural = "GST Bulk Requests"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Bulk Request {self.batch_id} - {self.user.email}"

    @property
    def is_completed(self):
        """Check if bulk request is completed"""
        return self.status == "completed"

    @property
    def success_rate(self):
        """Calculate success rate percentage"""
        if self.processed_records > 0:
            return (self.successful_records / self.processed_records) * 100
        return 0

    def update_progress(self):
        """Update progress percentage"""
        if self.total_records > 0:
            self.progress_percentage = (
                self.processed_records / self.total_records
            ) * 100
            self.save(update_fields=["progress_percentage"])


class GSTWebhook(models.Model):
    """Webhook configurations for GST events"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="gst_webhooks"
    )

    # Webhook configuration
    name = models.CharField(max_length=100)
    url = models.URLField()
    secret_key = models.CharField(
        max_length=100, help_text="Secret key for webhook verification"
    )

    # Event types
    events = models.JSONField(
        default=list, help_text="List of events to trigger webhook"
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Retry configuration
    max_retries = models.IntegerField(default=3)
    retry_delay_seconds = models.IntegerField(default=60)

    # Statistics
    total_deliveries = models.IntegerField(default=0)
    successful_deliveries = models.IntegerField(default=0)
    failed_deliveries = models.IntegerField(default=0)
    last_delivery_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "gst_webhooks"
        verbose_name = "GST Webhook"
        verbose_name_plural = "GST Webhooks"

    def __str__(self):
        return f"{self.name} - {self.user.email}"

    @property
    def success_rate(self):
        """Calculate webhook success rate"""
        if self.total_deliveries > 0:
            return (self.successful_deliveries / self.total_deliveries) * 100
        return 0


class GSTWebhookDelivery(models.Model):
    """Webhook delivery logs"""

    webhook = models.ForeignKey(
        GSTWebhook, on_delete=models.CASCADE, related_name="deliveries"
    )
    request = models.ForeignKey(
        GSTRequest,
        on_delete=models.CASCADE,
        related_name="webhook_deliveries",
        null=True,
        blank=True,
    )

    # Delivery details
    event_type = models.CharField(max_length=50)
    payload = models.JSONField()

    # HTTP details
    http_status_code = models.IntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    response_time_ms = models.IntegerField(null=True, blank=True)

    # Retry information
    attempt_number = models.IntegerField(default=1)
    max_attempts = models.IntegerField(default=3)

    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("delivered", "Delivered"),
            ("failed", "Failed"),
            ("retrying", "Retrying"),
        ],
        default="pending",
    )

    error_message = models.TextField(blank=True)

    # Timestamps
    scheduled_at = models.DateTimeField()
    delivered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "gst_webhook_deliveries"
        verbose_name = "GST Webhook Delivery"
        verbose_name_plural = "GST Webhook Deliveries"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.webhook.name} - {self.event_type} - {self.status}"

    @property
    def is_successful(self):
        """Check if delivery was successful"""
        return self.status == "delivered" and 200 <= (self.http_status_code or 0) < 300
