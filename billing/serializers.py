from decimal import Decimal

from rest_framework import serializers

from django.core.validators import MinValueValidator

from .models import Invoice, Payment, Subscription, SubscriptionPlan


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """Serializer for Subscription Plan model"""

    class Meta:
        model = SubscriptionPlan
        fields = [
            "id",
            "name",
            "description",
            "monthly_price",
            "yearly_price",
            "monthly_credits",
            "yearly_credits",
            "max_api_keys",
            "rate_limit_per_minute",
            "rate_limit_per_hour",
            "rate_limit_per_day",
            "support_level",
            "stripe_monthly_price_id",
            "stripe_yearly_price_id",
            "stripe_product_id",
            "razorpay_monthly_plan_id",
            "razorpay_yearly_plan_id",
            "razorpay_product_id",
            "is_active",
            "is_popular",
            "sort_order",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class UserSubscriptionSerializer(serializers.ModelSerializer):
    """Serializer for User Subscription model"""

    plan_details = SubscriptionPlanSerializer(source="plan", read_only=True)
    days_remaining = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = Subscription
        fields = [
            "id",
            "user",
            "plan",
            "plan_details",
            "billing_cycle",
            "status",
            "trial_start",
            "trial_end",
            "current_period_start",
            "current_period_end",
            "canceled_at",
            "stripe_subscription_id",
            "stripe_customer_id",
            "razorpay_subscription_id",
            "razorpay_customer_id",
            "payment_gateway",
            "credits_used_this_period",
            "credits_remaining_this_period",
            "created_at",
            "updated_at",
            "days_remaining",
            "is_expired",
        ]
        read_only_fields = [
            "id",
            "user",
            "stripe_subscription_id",
            "stripe_customer_id",
            "created_at",
            "updated_at",
            "days_remaining",
            "is_expired",
        ]

    def get_days_remaining(self, obj):
        """Calculate days remaining in subscription"""
        if obj.current_period_end:
            from django.utils import timezone

            remaining = (obj.current_period_end.date() - timezone.now().date()).days
            return max(0, remaining)
        return None

    def get_is_expired(self, obj):
        """Check if subscription is expired"""
        if obj.current_period_end:
            from django.utils import timezone

            return obj.current_period_end.date() < timezone.now().date()
        return False


class SubscriptionCreateSerializer(serializers.Serializer):
    """Serializer for creating a new subscription"""

    plan_id = serializers.IntegerField()
    payment_method_id = serializers.CharField(
        max_length=200, help_text="Stripe payment method ID"
    )
    auto_renew = serializers.BooleanField(default=True)
    discount_code = serializers.CharField(
        max_length=50, required=False, help_text="Optional discount code"
    )

    def validate_plan_id(self, value):
        """Validate that the plan exists and is active"""
        try:
            plan = SubscriptionPlan.objects.get(id=value, is_active=True)
            return value
        except SubscriptionPlan.DoesNotExist:
            raise serializers.ValidationError("Invalid or inactive subscription plan")

    def validate_discount_code(self, value):
        """Validate discount code if provided"""
        if value:
            # Discount functionality not implemented yet
            raise serializers.ValidationError(
                "Discount codes are not currently supported"
            )

        return value


class SubscriptionUpdateSerializer(serializers.Serializer):
    """Serializer for updating subscription settings"""

    auto_renew = serializers.BooleanField(required=False)


class InvoiceSerializer(serializers.ModelSerializer):
    """Serializer for Invoice model"""

    subscription_plan_name = serializers.CharField(
        source="subscription.plan.name", read_only=True
    )

    class Meta:
        model = Invoice
        fields = [
            "id",
            "user",
            "subscription",
            "subscription_plan_name",
            "invoice_number",
            "subtotal",
            "tax_amount",
            "total_amount",
            "status",
            "issue_date",
            "due_date",
            "paid_at",
            "stripe_invoice_id",
            "stripe_payment_intent_id",
            "razorpay_invoice_id",
            "razorpay_order_id",
            "stripe_payment_intent_id",
            "razorpay_invoice_id",
            "razorpay_order_id",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "user",
            "invoice_number",
            "stripe_invoice_id",
            "created_at",
            "updated_at",
        ]


class PaymentSerializer(serializers.ModelSerializer):
    """Serializer for Payment model"""

    invoice_number = serializers.CharField(
        source="invoice.invoice_number", read_only=True
    )

    class Meta:
        model = Payment
        fields = [
            "id",
            "user",
            "invoice",
            "invoice_number",
            "amount",
            "currency",
            "payment_method",
            "status",
            "stripe_payment_intent_id",
            "stripe_charge_id",
            "razorpay_payment_id",
            "razorpay_order_id",
            "payment_gateway",
            "razorpay_payment_id",
            "razorpay_order_id",
            "payment_gateway",
            "failure_code",
            "failure_message",
            "processed_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "user",
            "stripe_payment_intent_id",
            "stripe_charge_id",
            "created_at",
            "updated_at",
        ]


class PaymentCreateSerializer(serializers.Serializer):
    """Serializer for creating a payment"""

    invoice_id = serializers.IntegerField()
    payment_method_id = serializers.CharField(
        max_length=200, help_text="Stripe payment method ID"
    )

    def validate_invoice_id(self, value):
        """Validate that the invoice exists and belongs to the user"""
        request = self.context.get("request")
        if not request:
            raise serializers.ValidationError("Request context required")

        try:
            invoice = Invoice.objects.get(id=value, user=request.user)
            if invoice.status == "paid":
                raise serializers.ValidationError("Invoice is already paid")
            return value
        except Invoice.DoesNotExist:
            raise serializers.ValidationError("Invoice not found")


# Discount functionality not implemented yet
# class DiscountSerializer(serializers.ModelSerializer):
#     """Serializer for Discount model"""
#     pass


class DiscountValidationSerializer(serializers.Serializer):
    """Serializer for validating discount codes"""

    code = serializers.CharField(max_length=50)
    plan_id = serializers.IntegerField(required=False)

    def validate_code(self, value):
        """Validate discount code format"""
        raise serializers.ValidationError("Discount codes are not currently supported")


class BillingStatsSerializer(serializers.Serializer):
    """Serializer for billing statistics"""

    total_revenue = serializers.DecimalField(max_digits=10, decimal_places=2)
    monthly_revenue = serializers.DecimalField(max_digits=10, decimal_places=2)
    active_subscriptions = serializers.IntegerField()
    pending_invoices = serializers.IntegerField()
    overdue_invoices = serializers.IntegerField()
    total_customers = serializers.IntegerField()
    churn_rate = serializers.FloatField()
    average_revenue_per_user = serializers.DecimalField(max_digits=10, decimal_places=2)


class UserBillingStatsSerializer(serializers.Serializer):
    """Serializer for user-specific billing statistics"""

    current_subscription = UserSubscriptionSerializer()
    total_spent = serializers.DecimalField(max_digits=10, decimal_places=2)
    total_invoices = serializers.IntegerField()
    pending_invoices = serializers.IntegerField()
    last_payment_date = serializers.DateTimeField()
    next_billing_date = serializers.DateField()
    subscription_status = serializers.CharField()


class InvoiceDownloadSerializer(serializers.Serializer):
    """Serializer for invoice download request"""

    format = serializers.ChoiceField(
        choices=[("pdf", "PDF"), ("html", "HTML")], default="pdf"
    )


class SubscriptionCancellationSerializer(serializers.Serializer):
    """Serializer for subscription cancellation"""

    reason = serializers.ChoiceField(
        choices=[
            ("too_expensive", "Too expensive"),
            ("not_using", "Not using enough"),
            ("missing_features", "Missing features"),
            ("poor_support", "Poor customer support"),
            ("switching_provider", "Switching to another provider"),
            ("other", "Other"),
        ],
        required=False,
    )

    feedback = serializers.CharField(
        max_length=1000,
        required=False,
        help_text="Optional feedback about the cancellation",
    )

    cancel_immediately = serializers.BooleanField(
        default=False, help_text="Cancel immediately or at the end of billing period"
    )


class WebhookEventSerializer(serializers.Serializer):
    """Serializer for webhook events from payment gateways"""

    event_type = serializers.CharField(help_text="Type of webhook event")
    event_id = serializers.CharField(help_text="Unique event identifier")
    data = serializers.DictField(help_text="Event payload data")
    created = serializers.IntegerField(help_text="Event creation timestamp")
    
    class Meta:
        examples = {
            "stripe": {
                "event_type": "payment_intent.succeeded",
                "event_id": "evt_1234567890",
                "data": {"object": {"id": "pi_1234567890", "amount": 2000}},
                "created": 1640995200
            },
            "razorpay": {
                "event_type": "payment.captured",
                "event_id": "event_1234567890",
                "data": {"payment": {"entity": {"id": "pay_1234567890", "amount": 2000}}},
                "created": 1640995200
            }
        }


class PaymentGatewayConfigSerializer(serializers.Serializer):
    """Serializer for payment gateway configuration"""
    
    gateway = serializers.ChoiceField(
        choices=[("stripe", "Stripe"), ("razorpay", "RazorpayX")],
        help_text="Payment gateway to use"
    )
    currency = serializers.CharField(
        max_length=3, 
        default="USD",
        help_text="Currency code (USD, INR, etc.)"
    )
    return_url = serializers.URLField(
        required=False,
        help_text="URL to redirect after payment completion"
    )
    cancel_url = serializers.URLField(
        required=False,
        help_text="URL to redirect after payment cancellation"
    )
