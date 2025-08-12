import uuid

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication"""

    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with an email and password"""
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with an email and password"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom User model for GST Verification SaaS"""

    # Remove username field, use email as primary identifier
    username = None
    email = models.EmailField(unique=True)

    # Additional user fields
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    company_name = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    # Account status
    is_verified = models.BooleanField(default=False)
    is_premium = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    # Subscription related
    subscription_status = models.CharField(
        max_length=20,
        choices=[
            ("trial", "Trial"),
            ("active", "Active"),
            ("past_due", "Past Due"),
            ("canceled", "Canceled"),
            ("unpaid", "Unpaid"),
        ],
        default="trial",
    )

    trial_ends_at = models.DateTimeField(null=True, blank=True)
    subscription_ends_at = models.DateTimeField(null=True, blank=True)

    # Stripe customer ID
    stripe_customer_id = models.CharField(max_length=100, blank=True, null=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

    class Meta:
        db_table = "auth_user"
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def is_trial_active(self):
        """Check if user's trial is still active"""
        if self.trial_ends_at:
            return timezone.now() < self.trial_ends_at
        return False

    @property
    def is_subscription_active(self):
        """Check if user's subscription is active"""
        return self.subscription_status == "active"

    @property
    def can_use_api(self):
        """Check if user can use the API (trial or active subscription)"""
        return self.is_trial_active or self.is_subscription_active

    def save(self, *args, **kwargs):
        # Set trial period for new users (7 days)
        if not self.pk and not self.trial_ends_at:
            self.trial_ends_at = timezone.now() + timezone.timedelta(days=7)
        super().save(*args, **kwargs)


class UserProfile(models.Model):
    """Extended user profile information"""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")

    # Business information
    business_type = models.CharField(
        max_length=50,
        choices=[
            ("individual", "Individual"),
            ("startup", "Startup"),
            ("small_business", "Small Business"),
            ("enterprise", "Enterprise"),
            ("agency", "Agency"),
        ],
        default="individual",
    )

    # Address information
    address_line_1 = models.CharField(max_length=255, blank=True)
    address_line_2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, default="India")

    # Preferences
    timezone = models.CharField(max_length=50, default="Asia/Kolkata")
    language = models.CharField(max_length=10, default="en")

    # Marketing preferences
    marketing_emails = models.BooleanField(default=True)
    product_updates = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_profiles"
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"{self.user.email} - Profile"


class UserActivity(models.Model):
    """Track user activity and login history"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="activities")

    activity_type = models.CharField(
        max_length=50,
        choices=[
            ("login", "Login"),
            ("logout", "Logout"),
            ("api_call", "API Call"),
            ("subscription_change", "Subscription Change"),
            ("profile_update", "Profile Update"),
        ],
    )

    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Additional metadata
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_activities"
        verbose_name = "User Activity"
        verbose_name_plural = "User Activities"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} - {self.activity_type} - {self.created_at}"
