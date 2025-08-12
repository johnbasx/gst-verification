import logging
from datetime import datetime, timedelta
from decimal import Decimal

import stripe
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from django.conf import settings
from django.db import models, transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone

from api_management.models import APIUsage
from authentication.models import UserActivity

from .models import Invoice, Payment, Subscription, SubscriptionPlan
from .serializers import (
    BillingStatsSerializer,
    DiscountValidationSerializer,
    InvoiceDownloadSerializer,
    InvoiceSerializer,
    PaymentCreateSerializer,
    PaymentSerializer,
    SubscriptionCancellationSerializer,
    SubscriptionCreateSerializer,
    SubscriptionPlanSerializer,
    SubscriptionUpdateSerializer,
    UserBillingStatsSerializer,
    UserSubscriptionSerializer,
    WebhookEventSerializer,
)

# Configure Stripe
stripe.api_key = getattr(settings, "STRIPE_SECRET_KEY", "")
logger = logging.getLogger(__name__)


class SubscriptionPlanListView(generics.ListAPIView):
    """List all active subscription plans"""

    queryset = SubscriptionPlan.objects.filter(is_active=True).order_by(
        "sort_order", "monthly_price"
    )
    serializer_class = SubscriptionPlanSerializer
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="List subscription plans",
        description="Get all active subscription plans with their features and pricing",
        tags=["Billing"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class UserSubscriptionView(APIView):
    """Manage user subscriptions"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Get user subscription",
        description="Get current user's subscription details",
        responses={200: UserSubscriptionSerializer},
        tags=["Billing"],
    )
    def get(self, request):
        """Get current user's subscription"""
        try:
            subscription = Subscription.objects.select_related("plan").get(
                user=request.user, status__in=["active", "trialing"]
            )
            serializer = UserSubscriptionSerializer(subscription)

            # Log activity
            UserActivity.objects.create(
                user=request.user,
                activity_type="subscription_viewed",
                description="Viewed subscription details",
            )

            return Response(serializer.data)
        except Subscription.DoesNotExist:
            return Response(
                {"detail": "No active subscription found"},
                status=status.HTTP_404_NOT_FOUND,
            )

    @extend_schema(
        summary="Create subscription",
        description="Create a new subscription for the user",
        request=SubscriptionCreateSerializer,
        responses={201: UserSubscriptionSerializer},
        tags=["Billing"],
    )
    def post(self, request):
        """Create a new subscription"""
        serializer = SubscriptionCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # Get plan
                plan = SubscriptionPlan.objects.get(
                    id=serializer.validated_data["plan_id"]
                )

                # Check for existing active subscription
                existing_subscription = Subscription.objects.filter(
                    user=request.user, status__in=["active", "trialing"]
                ).first()

                if existing_subscription:
                    return Response(
                        {"detail": "User already has an active subscription"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Calculate pricing (discount functionality not implemented)
                final_price = (
                    plan.monthly_price
                    if billing_cycle == "monthly"
                    else plan.yearly_price
                )

                # Create Stripe subscription
                stripe_subscription = stripe.Subscription.create(
                    customer=self._get_or_create_stripe_customer(request.user),
                    items=[
                        {
                            "price_data": {
                                "currency": plan.currency.lower(),
                                "product_data": {
                                    "name": plan.name,
                                    "description": plan.description,
                                },
                                "unit_amount": int(final_price * 100),
                                "recurring": {
                                    "interval": "month"
                                    if plan.billing_cycle == "monthly"
                                    else "year"
                                },
                            },
                        }
                    ],
                    default_payment_method=serializer.validated_data[
                        "payment_method_id"
                    ],
                    expand=["latest_invoice.payment_intent"],
                )

                # Create subscription record
                subscription = Subscription.objects.create(
                    user=request.user,
                    plan=plan,
                    status="active",
                    start_date=timezone.now().date(),
                    end_date=self._calculate_end_date(plan),
                    auto_renew=serializer.validated_data["auto_renew"],
                    stripe_subscription_id=stripe_subscription.id,
                )

                # Discount usage tracking not implemented

                # Log activity
                UserActivity.objects.create(
                    user=request.user,
                    activity_type="subscription_created",
                    description=f"Created subscription for plan: {plan.name}",
                )

                serializer = UserSubscriptionSerializer(subscription)
                return Response(serializer.data, status=status.HTTP_201_CREATED)

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating subscription: {str(e)}")
            return Response(
                {"detail": f"Payment processing error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            logger.error(f"Error creating subscription: {str(e)}")
            return Response(
                {"detail": "Failed to create subscription"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @extend_schema(
        summary="Update subscription",
        description="Update subscription settings",
        request=SubscriptionUpdateSerializer,
        responses={200: UserSubscriptionSerializer},
        tags=["Billing"],
    )
    def patch(self, request):
        """Update subscription settings"""
        try:
            subscription = Subscription.objects.get(
                user=request.user, status__in=["active", "trialing"]
            )
        except Subscription.DoesNotExist:
            return Response(
                {"detail": "No active subscription found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = SubscriptionUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Update auto-renewal setting
            if "auto_renew" in serializer.validated_data:
                subscription.auto_renew = serializer.validated_data["auto_renew"]
                subscription.save()

                # Update Stripe subscription
                if subscription.stripe_subscription_id:
                    stripe.Subscription.modify(
                        subscription.stripe_subscription_id,
                        cancel_at_period_end=not subscription.auto_renew,
                    )

            # Log activity
            UserActivity.objects.create(
                user=request.user,
                activity_type="subscription_updated",
                description="Updated subscription settings",
            )

            serializer = UserSubscriptionSerializer(subscription)
            return Response(serializer.data)

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error updating subscription: {str(e)}")
            return Response(
                {"detail": f"Payment processing error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _get_or_create_stripe_customer(self, user):
        """Get or create Stripe customer for user"""
        if hasattr(user, "stripe_customer_id") and user.stripe_customer_id:
            return user.stripe_customer_id

        customer = stripe.Customer.create(
            email=user.email,
            name=f"{user.first_name} {user.last_name}".strip(),
            metadata={"user_id": user.id},
        )

        # Save customer ID to user model (you might need to add this field)
        # user.stripe_customer_id = customer.id
        # user.save()

        return customer.id

    def _calculate_end_date(self, plan):
        """Calculate subscription end date based on billing cycle"""
        start_date = timezone.now().date()
        if plan.billing_cycle == "monthly":
            return start_date + timedelta(days=30)
        elif plan.billing_cycle == "yearly":
            return start_date + timedelta(days=365)
        return start_date + timedelta(days=30)


class SubscriptionCancelView(APIView):
    """Cancel user subscription"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Cancel subscription",
        description="Cancel the user's current subscription",
        request=SubscriptionCancellationSerializer,
        responses={200: {"description": "Subscription cancelled successfully"}},
        tags=["Billing"],
    )
    def post(self, request):
        """Cancel subscription"""
        try:
            subscription = Subscription.objects.get(
                user=request.user, status__in=["active", "trialing"]
            )
        except Subscription.DoesNotExist:
            return Response(
                {"detail": "No active subscription found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = SubscriptionCancellationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            cancel_immediately = serializer.validated_data.get(
                "cancel_immediately", False
            )

            if cancel_immediately:
                # Cancel immediately
                subscription.status = "cancelled"
                subscription.end_date = timezone.now().date()
                subscription.save()

                # Cancel Stripe subscription immediately
                if subscription.stripe_subscription_id:
                    stripe.Subscription.delete(subscription.stripe_subscription_id)
            else:
                # Cancel at period end
                subscription.auto_renew = False
                subscription.save()

                # Set Stripe subscription to cancel at period end
                if subscription.stripe_subscription_id:
                    stripe.Subscription.modify(
                        subscription.stripe_subscription_id, cancel_at_period_end=True
                    )

            # Log activity with cancellation reason
            reason = serializer.validated_data.get("reason", "not_specified")
            feedback = serializer.validated_data.get("feedback", "")

            UserActivity.objects.create(
                user=request.user,
                activity_type="subscription_cancelled",
                description=f"Cancelled subscription. Reason: {reason}. Feedback: {feedback}",
            )

            return Response(
                {
                    "detail": "Subscription cancelled successfully",
                    "cancelled_immediately": cancel_immediately,
                }
            )

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error cancelling subscription: {str(e)}")
            return Response(
                {"detail": f"Payment processing error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class InvoiceListView(generics.ListAPIView):
    """List user invoices"""

    serializer_class = InvoiceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Invoice.objects.filter(user=self.request.user).order_by("-created_at")

    @extend_schema(
        summary="List user invoices",
        description="Get all invoices for the authenticated user",
        tags=["Billing"],
    )
    def get(self, request, *args, **kwargs):
        # Log activity
        UserActivity.objects.create(
            user=request.user,
            activity_type="invoices_viewed",
            description="Viewed invoice list",
        )
        return super().get(request, *args, **kwargs)


class InvoiceDetailView(generics.RetrieveAPIView):
    """Get invoice details"""

    serializer_class = InvoiceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Invoice.objects.filter(user=self.request.user)

    @extend_schema(
        summary="Get invoice details",
        description="Get detailed information about a specific invoice",
        tags=["Billing"],
    )
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)

        # Log activity
        UserActivity.objects.create(
            user=request.user,
            activity_type="invoice_viewed",
            description=f'Viewed invoice details: {kwargs.get("pk")}',
        )

        return response


class PaymentCreateView(APIView):
    """Create a payment for an invoice"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Create payment",
        description="Create a payment for an outstanding invoice",
        request=PaymentCreateSerializer,
        responses={201: PaymentSerializer},
        tags=["Billing"],
    )
    def post(self, request):
        """Create payment for invoice"""
        serializer = PaymentCreateSerializer(
            data=request.data, context={"request": request}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                invoice = Invoice.objects.get(
                    id=serializer.validated_data["invoice_id"], user=request.user
                )

                # Create Stripe payment intent
                payment_intent = stripe.PaymentIntent.create(
                    amount=int(invoice.total_amount * 100),
                    currency=invoice.currency.lower(),
                    payment_method=serializer.validated_data["payment_method_id"],
                    confirm=True,
                    metadata={"invoice_id": invoice.id, "user_id": request.user.id},
                )

                # Create payment record
                payment = Payment.objects.create(
                    user=request.user,
                    invoice=invoice,
                    amount=invoice.total_amount,
                    currency=invoice.currency,
                    payment_method="stripe",
                    status="completed"
                    if payment_intent.status == "succeeded"
                    else "pending",
                    stripe_payment_intent_id=payment_intent.id,
                )

                # Update invoice status if payment succeeded
                if payment_intent.status == "succeeded":
                    invoice.status = "paid"
                    invoice.paid_date = timezone.now()
                    invoice.save()

                # Log activity
                UserActivity.objects.create(
                    user=request.user,
                    activity_type="payment_created",
                    description=f"Created payment for invoice: {invoice.invoice_number}",
                )

                serializer = PaymentSerializer(payment)
                return Response(serializer.data, status=status.HTTP_201_CREATED)

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating payment: {str(e)}")
            return Response(
                {"detail": f"Payment processing error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            logger.error(f"Error creating payment: {str(e)}")
            return Response(
                {"detail": "Failed to process payment"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# DiscountValidationView removed - Discount model not implemented


class UserBillingStatsView(APIView):
    """Get user billing statistics"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Get user billing stats",
        description="Get billing statistics for the authenticated user",
        responses={200: UserBillingStatsSerializer},
        tags=["Billing"],
    )
    def get(self, request):
        """Get user billing statistics"""
        user = request.user

        # Get current subscription
        current_subscription = (
            Subscription.objects.filter(user=user, status__in=["active", "trialing"])
            .select_related("plan")
            .first()
        )

        # Calculate statistics
        total_spent = Payment.objects.filter(user=user, status="completed").aggregate(
            total=models.Sum("amount")
        )["total"] or Decimal("0.00")

        total_invoices = Invoice.objects.filter(user=user).count()
        pending_invoices = Invoice.objects.filter(user=user, status="pending").count()

        last_payment = (
            Payment.objects.filter(user=user, status="completed")
            .order_by("-created_at")
            .first()
        )

        # Calculate next billing date
        next_billing_date = None
        if current_subscription and current_subscription.end_date:
            next_billing_date = current_subscription.end_date

        stats_data = {
            "current_subscription": current_subscription,
            "total_spent": total_spent,
            "total_invoices": total_invoices,
            "pending_invoices": pending_invoices,
            "last_payment_date": last_payment.created_at if last_payment else None,
            "next_billing_date": next_billing_date,
            "subscription_status": current_subscription.status
            if current_subscription
            else "none",
        }

        serializer = UserBillingStatsSerializer(stats_data)

        # Log activity
        UserActivity.objects.create(
            user=request.user,
            activity_type="billing_stats_viewed",
            description="Viewed billing statistics",
        )

        return Response(serializer.data)


@api_view(["POST"])
@permission_classes([permissions.AllowAny])
@extend_schema(
    summary="Stripe webhook",
    description="Handle Stripe webhook events",
    request=WebhookEventSerializer,
    responses={200: {"description": "Webhook processed successfully"}},
    tags=["Billing"],
)
def stripe_webhook(request):
    """Handle Stripe webhook events"""
    payload = request.body
    sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")
    endpoint_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError:
        logger.error("Invalid payload in Stripe webhook")
        return Response({"error": "Invalid payload"}, status=400)
    except stripe.error.SignatureVerificationError:
        logger.error("Invalid signature in Stripe webhook")
        return Response({"error": "Invalid signature"}, status=400)

    # Handle the event
    try:
        if event["type"] == "invoice.payment_succeeded":
            _handle_payment_succeeded(event["data"]["object"])
        elif event["type"] == "invoice.payment_failed":
            _handle_payment_failed(event["data"]["object"])
        elif event["type"] == "customer.subscription.deleted":
            _handle_subscription_deleted(event["data"]["object"])
        elif event["type"] == "customer.subscription.updated":
            _handle_subscription_updated(event["data"]["object"])
        else:
            logger.info(f"Unhandled Stripe event type: {event['type']}")

    except Exception as e:
        logger.error(f"Error handling Stripe webhook: {str(e)}")
        return Response({"error": "Webhook processing failed"}, status=500)

    return Response({"status": "success"})


def _handle_payment_succeeded(invoice_data):
    """Handle successful payment webhook"""
    try:
        subscription_id = invoice_data.get("subscription")
        if subscription_id:
            subscription = Subscription.objects.get(
                stripe_subscription_id=subscription_id
            )

            # Update subscription status
            subscription.status = "active"
            subscription.save()

            # Create or update invoice
            invoice, created = Invoice.objects.get_or_create(
                stripe_invoice_id=invoice_data["id"],
                defaults={
                    "user": subscription.user,
                    "subscription": subscription,
                    "amount": Decimal(invoice_data["amount_paid"]) / 100,
                    "currency": invoice_data["currency"].upper(),
                    "status": "paid",
                    "paid_date": timezone.now(),
                },
            )

            if not created:
                invoice.status = "paid"
                invoice.paid_date = timezone.now()
                invoice.save()

    except Subscription.DoesNotExist:
        logger.error(f"Subscription not found for Stripe ID: {subscription_id}")
    except Exception as e:
        logger.error(f"Error handling payment succeeded: {str(e)}")


def _handle_payment_failed(invoice_data):
    """Handle failed payment webhook"""
    try:
        subscription_id = invoice_data.get("subscription")
        if subscription_id:
            subscription = Subscription.objects.get(
                stripe_subscription_id=subscription_id
            )

            # Update subscription status
            subscription.status = "past_due"
            subscription.save()

            # Update invoice status
            try:
                invoice = Invoice.objects.get(stripe_invoice_id=invoice_data["id"])
                invoice.status = "failed"
                invoice.save()
            except Invoice.DoesNotExist:
                pass

    except Subscription.DoesNotExist:
        logger.error(f"Subscription not found for Stripe ID: {subscription_id}")
    except Exception as e:
        logger.error(f"Error handling payment failed: {str(e)}")


def _handle_subscription_deleted(subscription_data):
    """Handle subscription deletion webhook"""
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=subscription_data["id"]
        )
        subscription.status = "cancelled"
        subscription.end_date = timezone.now().date()
        subscription.save()

    except Subscription.DoesNotExist:
        logger.error(f"Subscription not found for Stripe ID: {subscription_data['id']}")
    except Exception as e:
        logger.error(f"Error handling subscription deleted: {str(e)}")


def _handle_subscription_updated(subscription_data):
    """Handle subscription update webhook"""
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=subscription_data["id"]
        )

        # Update status based on Stripe status
        stripe_status = subscription_data["status"]
        if stripe_status == "active":
            subscription.status = "active"
        elif stripe_status == "canceled":
            subscription.status = "cancelled"
        elif stripe_status == "past_due":
            subscription.status = "past_due"
        elif stripe_status == "trialing":
            subscription.status = "trialing"

        subscription.save()

    except Subscription.DoesNotExist:
        logger.error(f"Subscription not found for Stripe ID: {subscription_data['id']}")
    except Exception as e:
        logger.error(f"Error handling subscription updated: {str(e)}")
