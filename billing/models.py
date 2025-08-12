import uuid
from decimal import Decimal

from django.conf import settings
from django.db import models
from django.utils import timezone


class SubscriptionPlan(models.Model):
    """Subscription plans for the SaaS platform"""

    name = models.CharField(max_length=100)
    description = models.TextField()

    # Pricing
    monthly_price = models.DecimalField(max_digits=10, decimal_places=2)
    yearly_price = models.DecimalField(max_digits=10, decimal_places=2)

    # Credits included
    monthly_credits = models.IntegerField(help_text="Credits included per month")
    yearly_credits = models.IntegerField(help_text="Credits included per year")

    # Features
    max_api_keys = models.IntegerField(default=5)
    rate_limit_per_minute = models.IntegerField(default=100)
    rate_limit_per_hour = models.IntegerField(default=2000)
    rate_limit_per_day = models.IntegerField(default=20000)

    # Support level
    support_level = models.CharField(
        max_length=20,
        choices=[
            ("basic", "Basic"),
            ("priority", "Priority"),
            ("premium", "Premium"),
        ],
        default="basic",
    )

    # Stripe integration
    stripe_monthly_price_id = models.CharField(max_length=100, blank=True)
    stripe_yearly_price_id = models.CharField(max_length=100, blank=True)
    stripe_product_id = models.CharField(max_length=100, blank=True)
    
    # RazorpayX integration
    razorpay_monthly_plan_id = models.CharField(max_length=100, blank=True)
    razorpay_yearly_plan_id = models.CharField(max_length=100, blank=True)
    razorpay_product_id = models.CharField(max_length=100, blank=True)

    # Status and display
    is_active = models.BooleanField(default=True)
    is_popular = models.BooleanField(default=False)
    sort_order = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "subscription_plans"
        verbose_name = "Subscription Plan"
        verbose_name_plural = "Subscription Plans"
        ordering = ["sort_order", "monthly_price"]

    def __str__(self):
        return self.name

    @property
    def yearly_discount_percentage(self):
        """Calculate yearly discount percentage"""
        if self.monthly_price > 0:
            monthly_yearly_total = self.monthly_price * 12
            if monthly_yearly_total > self.yearly_price:
                discount = monthly_yearly_total - self.yearly_price
                return round((discount / monthly_yearly_total) * 100, 1)
        return 0

    @property
    def monthly_price_per_credit(self):
        """Calculate price per credit for monthly plan"""
        if self.monthly_credits > 0:
            return self.monthly_price / self.monthly_credits
        return 0

    @property
    def yearly_price_per_credit(self):
        """Calculate price per credit for yearly plan"""
        if self.yearly_credits > 0:
            return self.yearly_price / self.yearly_credits
        return 0


class Subscription(models.Model):
    """User subscriptions"""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="subscription"
    )
    plan = models.ForeignKey(
        SubscriptionPlan, on_delete=models.PROTECT, related_name="subscriptions"
    )

    # Subscription details
    billing_cycle = models.CharField(
        max_length=10,
        choices=[
            ("monthly", "Monthly"),
            ("yearly", "Yearly"),
        ],
        default="monthly",
    )

    status = models.CharField(
        max_length=20,
        choices=[
            ("trial", "Trial"),
            ("active", "Active"),
            ("past_due", "Past Due"),
            ("canceled", "Canceled"),
            ("unpaid", "Unpaid"),
            ("paused", "Paused"),
        ],
        default="trial",
    )

    # Dates
    trial_start = models.DateTimeField(null=True, blank=True)
    trial_end = models.DateTimeField(null=True, blank=True)
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()
    canceled_at = models.DateTimeField(null=True, blank=True)

    # Payment gateway integration
    stripe_subscription_id = models.CharField(max_length=100, blank=True)
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    razorpay_subscription_id = models.CharField(max_length=100, blank=True)
    razorpay_customer_id = models.CharField(max_length=100, blank=True)
    
    # Payment gateway preference
    payment_gateway = models.CharField(
        max_length=20,
        choices=[
            ("stripe", "Stripe"),
            ("razorpay", "RazorpayX"),
        ],
        default="stripe",
    )

    # Credits tracking
    credits_used_this_period = models.DecimalField(
        max_digits=15, decimal_places=4, default=0.0000
    )
    credits_remaining_this_period = models.DecimalField(
        max_digits=15, decimal_places=4, default=0.0000
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "subscriptions"
        verbose_name = "Subscription"
        verbose_name_plural = "Subscriptions"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} - {self.plan.name} ({self.status})"

    @property
    def is_active(self):
        """Check if subscription is active"""
        return self.status in ["trial", "active"]

    @property
    def is_trial(self):
        """Check if subscription is in trial period"""
        return (
            self.status == "trial"
            and self.trial_end
            and timezone.now() < self.trial_end
        )

    @property
    def days_until_renewal(self):
        """Calculate days until next renewal"""
        if self.current_period_end:
            delta = self.current_period_end - timezone.now()
            return max(0, delta.days)
        return 0

    @property
    def credits_included_this_period(self):
        """Get credits included in current billing period"""
        if self.billing_cycle == "yearly":
            return self.plan.yearly_credits
        return self.plan.monthly_credits

    def reset_period_credits(self):
        """Reset credits for new billing period"""
        self.credits_used_this_period = 0
        self.credits_remaining_this_period = self.credits_included_this_period
        self.save()
        
        # Update user credits in api_management
        from api_management.models import UserCredits
        user_credits, created = UserCredits.objects.get_or_create(
            user=self.user,
            defaults={'balance': self.credits_included_this_period}
        )
        if not created:
            user_credits.balance += self.credits_included_this_period
            user_credits.save()

    def use_subscription_credits(self, amount):
        """Use subscription credits"""
        if self.credits_remaining_this_period >= amount:
            self.credits_remaining_this_period -= amount
            self.credits_used_this_period += amount
            self.save()
            return True
        return False


class Invoice(models.Model):
    """Billing invoices"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="invoices"
    )
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="invoices",
        null=True,
        blank=True,
    )

    # Invoice details
    invoice_number = models.CharField(max_length=50, unique=True)

    # Amounts
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)

    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ("draft", "Draft"),
            ("open", "Open"),
            ("paid", "Paid"),
            ("void", "Void"),
            ("uncollectible", "Uncollectible"),
        ],
        default="draft",
    )

    # Dates
    issue_date = models.DateTimeField(auto_now_add=True)
    due_date = models.DateTimeField()
    paid_at = models.DateTimeField(null=True, blank=True)

    # Payment gateway integration
    stripe_invoice_id = models.CharField(max_length=100, blank=True)
    stripe_payment_intent_id = models.CharField(max_length=100, blank=True)
    razorpay_invoice_id = models.CharField(max_length=100, blank=True)
    razorpay_order_id = models.CharField(max_length=100, blank=True)

    # Billing period
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "invoices"
        verbose_name = "Invoice"
        verbose_name_plural = "Invoices"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Invoice {self.invoice_number} - {self.user.email}"

    def save(self, *args, **kwargs):
        if not self.invoice_number:
            self.invoice_number = self.generate_invoice_number()
        super().save(*args, **kwargs)

    def generate_invoice_number(self):
        """Generate unique invoice number"""
        import datetime

        now = datetime.datetime.now()
        prefix = f"INV-{now.year}{now.month:02d}"

        # Get the last invoice for this month
        last_invoice = (
            Invoice.objects.filter(invoice_number__startswith=prefix)
            .order_by("-invoice_number")
            .first()
        )

        if last_invoice:
            last_number = int(last_invoice.invoice_number.split("-")[-1])
            new_number = last_number + 1
        else:
            new_number = 1

        return f"{prefix}-{new_number:04d}"


class InvoiceItem(models.Model):
    """Individual items on an invoice"""

    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name="items")

    description = models.CharField(max_length=255)
    quantity = models.DecimalField(max_digits=10, decimal_places=4, default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "invoice_items"
        verbose_name = "Invoice Item"
        verbose_name_plural = "Invoice Items"

    def __str__(self):
        return f"{self.invoice.invoice_number} - {self.description}"

    def save(self, *args, **kwargs):
        self.total_price = self.quantity * self.unit_price
        super().save(*args, **kwargs)


class Payment(models.Model):
    """Payment records"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="payments"
    )
    invoice = models.ForeignKey(
        Invoice,
        on_delete=models.CASCADE,
        related_name="payments",
        null=True,
        blank=True,
    )

    # Payment details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default="USD")

    # Payment method
    payment_method = models.CharField(
        max_length=20,
        choices=[
            ("card", "Credit Card"),
            ("bank_transfer", "Bank Transfer"),
            ("paypal", "PayPal"),
            ("stripe", "Stripe"),
            ("razorpay", "RazorpayX"),
            ("upi", "UPI"),
            ("netbanking", "Net Banking"),
            ("wallet", "Wallet"),
        ],
        default="stripe",
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("processing", "Processing"),
            ("succeeded", "Succeeded"),
            ("failed", "Failed"),
            ("canceled", "Canceled"),
            ("refunded", "Refunded"),
        ],
        default="pending",
    )

    # Payment gateway integration
    stripe_payment_intent_id = models.CharField(max_length=100, blank=True)
    stripe_charge_id = models.CharField(max_length=100, blank=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True)
    razorpay_order_id = models.CharField(max_length=100, blank=True)
    
    # Gateway preference
    payment_gateway = models.CharField(
        max_length=20,
        choices=[
            ("stripe", "Stripe"),
            ("razorpay", "RazorpayX"),
        ],
        default="stripe",
    )

    # Failure information
    failure_code = models.CharField(max_length=50, blank=True)
    failure_message = models.TextField(blank=True)

    # Timestamps
    processed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "payments"
        verbose_name = "Payment"
        verbose_name_plural = "Payments"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Payment {self.id} - {self.user.email} - ${self.amount}"

    @property
    def is_successful(self):
        """Check if payment was successful"""
        return self.status == "succeeded"


class UsageAlert(models.Model):
    """Alerts for usage thresholds"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="usage_alerts"
    )

    # Alert configuration
    alert_type = models.CharField(
        max_length=25,
        choices=[
            ("credit_low", "Credits Running Low"),
            ("credit_exhausted", "Credits Exhausted"),
            ("rate_limit", "Rate Limit Exceeded"),
            ("subscription_expiring", "Subscription Expiring"),
        ],
    )

    threshold_percentage = models.IntegerField(
        help_text="Percentage threshold for alert"
    )

    # Status
    is_active = models.BooleanField(default=True)
    last_triggered_at = models.DateTimeField(null=True, blank=True)

    # Notification preferences
    email_notification = models.BooleanField(default=True)
    webhook_notification = models.BooleanField(default=False)
    webhook_url = models.URLField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usage_alerts"
        verbose_name = "Usage Alert"
        verbose_name_plural = "Usage Alerts"
        unique_together = ["user", "alert_type", "threshold_percentage"]

    def __str__(self):
        return f"{self.user.email} - {self.alert_type} - {self.threshold_percentage}%"
