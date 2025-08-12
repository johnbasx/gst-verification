import hashlib
import hmac
import json
import logging
from decimal import Decimal
from typing import Dict, Any

import razorpay
import stripe
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

from .models import Invoice, Payment, Subscription, SubscriptionPlan
from .serializers import WebhookEventSerializer
from authentication.models import User
from api_management.models import UserCredits

logger = logging.getLogger(__name__)

# Configure payment gateways
stripe.api_key = getattr(settings, "STRIPE_SECRET_KEY", "")
razorpay_client = razorpay.Client(
    auth=(
        getattr(settings, "RAZORPAY_KEY_ID", ""),
        getattr(settings, "RAZORPAY_KEY_SECRET", "")
    )
)


@api_view(["POST"])
@permission_classes([AllowAny])
@csrf_exempt
@extend_schema(
    summary="Stripe webhook handler",
    description="Handle Stripe webhook events for payments and subscriptions",
    request=WebhookEventSerializer,
    responses={
        200: {"description": "Webhook processed successfully"},
        400: {"description": "Invalid webhook payload or signature"},
        500: {"description": "Webhook processing failed"}
    },
    tags=["Billing"],
)
def stripe_webhook(request):
    """Enhanced Stripe webhook handler with comprehensive event processing"""
    payload = request.body
    sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")
    endpoint_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", "")

    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        logger.info(f"Received Stripe webhook event: {event['type']}")
        
    except ValueError as e:
        logger.error(f"Invalid payload in Stripe webhook: {str(e)}")
        return Response(
            {"error": "Invalid payload"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature in Stripe webhook: {str(e)}")
        return Response(
            {"error": "Invalid signature"}, 
            status=status.HTTP_400_BAD_REQUEST
        )

    # Process the event
    try:
        with transaction.atomic():
            event_type = event["type"]
            event_data = event["data"]["object"]
            
            # Payment events
            if event_type == "payment_intent.succeeded":
                _handle_stripe_payment_succeeded(event_data)
            elif event_type == "payment_intent.payment_failed":
                _handle_stripe_payment_failed(event_data)
            elif event_type == "payment_intent.canceled":
                _handle_stripe_payment_canceled(event_data)
                
            # Invoice events
            elif event_type == "invoice.payment_succeeded":
                _handle_stripe_invoice_payment_succeeded(event_data)
            elif event_type == "invoice.payment_failed":
                _handle_stripe_invoice_payment_failed(event_data)
            elif event_type == "invoice.finalized":
                _handle_stripe_invoice_finalized(event_data)
                
            # Subscription events
            elif event_type == "customer.subscription.created":
                _handle_stripe_subscription_created(event_data)
            elif event_type == "customer.subscription.updated":
                _handle_stripe_subscription_updated(event_data)
            elif event_type == "customer.subscription.deleted":
                _handle_stripe_subscription_deleted(event_data)
            elif event_type == "customer.subscription.trial_will_end":
                _handle_stripe_trial_will_end(event_data)
                
            # Customer events
            elif event_type == "customer.created":
                _handle_stripe_customer_created(event_data)
            elif event_type == "customer.updated":
                _handle_stripe_customer_updated(event_data)
                
            else:
                logger.info(f"Unhandled Stripe event type: {event_type}")
                
        return Response({"status": "success"})
        
    except Exception as e:
        logger.error(f"Error processing Stripe webhook: {str(e)}", exc_info=True)
        return Response(
            {"error": "Webhook processing failed"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(["POST"])
@permission_classes([AllowAny])
@csrf_exempt
@extend_schema(
    summary="RazorpayX webhook handler",
    description="Handle RazorpayX webhook events for payments and subscriptions",
    request=WebhookEventSerializer,
    responses={
        200: {"description": "Webhook processed successfully"},
        400: {"description": "Invalid webhook payload or signature"},
        500: {"description": "Webhook processing failed"}
    },
    tags=["Billing"],
)
def razorpay_webhook(request):
    """Enhanced RazorpayX webhook handler"""
    payload = request.body
    signature = request.META.get("HTTP_X_RAZORPAY_SIGNATURE")
    webhook_secret = getattr(settings, "RAZORPAY_WEBHOOK_SECRET", "")

    try:
        # Verify webhook signature
        if not _verify_razorpay_signature(payload, signature, webhook_secret):
            logger.error("Invalid signature in RazorpayX webhook")
            return Response(
                {"error": "Invalid signature"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Parse webhook data
        webhook_data = json.loads(payload.decode('utf-8'))
        event_type = webhook_data.get("event")
        event_data = webhook_data.get("payload", {})
        
        logger.info(f"Received RazorpayX webhook event: {event_type}")
        
    except (ValueError, json.JSONDecodeError) as e:
        logger.error(f"Invalid payload in RazorpayX webhook: {str(e)}")
        return Response(
            {"error": "Invalid payload"}, 
            status=status.HTTP_400_BAD_REQUEST
        )

    # Process the event
    try:
        with transaction.atomic():
            # Payment events
            if event_type == "payment.captured":
                _handle_razorpay_payment_captured(event_data)
            elif event_type == "payment.failed":
                _handle_razorpay_payment_failed(event_data)
            elif event_type == "payment.authorized":
                _handle_razorpay_payment_authorized(event_data)
                
            # Subscription events
            elif event_type == "subscription.activated":
                _handle_razorpay_subscription_activated(event_data)
            elif event_type == "subscription.charged":
                _handle_razorpay_subscription_charged(event_data)
            elif event_type == "subscription.cancelled":
                _handle_razorpay_subscription_cancelled(event_data)
            elif event_type == "subscription.completed":
                _handle_razorpay_subscription_completed(event_data)
                
            # Refund events
            elif event_type == "refund.created":
                _handle_razorpay_refund_created(event_data)
                
            else:
                logger.info(f"Unhandled RazorpayX event type: {event_type}")
                
        return Response({"status": "success"})
        
    except Exception as e:
        logger.error(f"Error processing RazorpayX webhook: {str(e)}", exc_info=True)
        return Response(
            {"error": "Webhook processing failed"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Stripe Event Handlers
def _handle_stripe_payment_succeeded(payment_data: Dict[str, Any]):
    """Handle successful Stripe payment"""
    payment_intent_id = payment_data["id"]
    amount = Decimal(payment_data["amount"]) / 100  # Convert from cents
    currency = payment_data["currency"].upper()
    
    try:
        # Find and update payment record
        payment = Payment.objects.get(stripe_payment_intent_id=payment_intent_id)
        payment.status = "succeeded"
        payment.processed_at = timezone.now()
        payment.save()
        
        # Update associated invoice if exists
        if payment.invoice:
            payment.invoice.status = "paid"
            payment.invoice.paid_at = timezone.now()
            payment.invoice.save()
            
        # If this is a subscription payment, activate subscription
        if payment.invoice and payment.invoice.subscription:
            subscription = payment.invoice.subscription
            subscription.status = "active"
            subscription.save()
            
        logger.info(f"Stripe payment succeeded: {payment_intent_id}")
        
    except Payment.DoesNotExist:
        logger.warning(f"Payment not found for Stripe payment intent: {payment_intent_id}")


def _handle_stripe_payment_failed(payment_data: Dict[str, Any]):
    """Handle failed Stripe payment"""
    payment_intent_id = payment_data["id"]
    failure_code = payment_data.get("last_payment_error", {}).get("code", "")
    failure_message = payment_data.get("last_payment_error", {}).get("message", "")
    
    try:
        payment = Payment.objects.get(stripe_payment_intent_id=payment_intent_id)
        payment.status = "failed"
        payment.failure_code = failure_code
        payment.failure_message = failure_message
        payment.processed_at = timezone.now()
        payment.save()
        
        logger.info(f"Stripe payment failed: {payment_intent_id} - {failure_message}")
        
    except Payment.DoesNotExist:
        logger.warning(f"Payment not found for Stripe payment intent: {payment_intent_id}")


def _handle_stripe_payment_canceled(payment_data: Dict[str, Any]):
    """Handle canceled Stripe payment"""
    payment_intent_id = payment_data["id"]
    
    try:
        payment = Payment.objects.get(stripe_payment_intent_id=payment_intent_id)
        payment.status = "canceled"
        payment.processed_at = timezone.now()
        payment.save()
        
        logger.info(f"Stripe payment canceled: {payment_intent_id}")
        
    except Payment.DoesNotExist:
        logger.warning(f"Payment not found for Stripe payment intent: {payment_intent_id}")


def _handle_stripe_invoice_payment_succeeded(invoice_data: Dict[str, Any]):
    """Handle successful Stripe invoice payment"""
    stripe_invoice_id = invoice_data["id"]
    subscription_id = invoice_data.get("subscription")
    
    try:
        # Update invoice
        invoice = Invoice.objects.get(stripe_invoice_id=stripe_invoice_id)
        invoice.status = "paid"
        invoice.paid_at = timezone.now()
        invoice.save()
        
        # Update subscription if exists
        if subscription_id and invoice.subscription:
            subscription = invoice.subscription
            subscription.status = "active"
            subscription.save()
            
            # Reset subscription credits
            subscription.reset_period_credits()
            
        logger.info(f"Stripe invoice payment succeeded: {stripe_invoice_id}")
        
    except Invoice.DoesNotExist:
        logger.warning(f"Invoice not found for Stripe invoice: {stripe_invoice_id}")


def _handle_stripe_invoice_payment_failed(invoice_data: Dict[str, Any]):
    """Handle failed Stripe invoice payment"""
    stripe_invoice_id = invoice_data["id"]
    subscription_id = invoice_data.get("subscription")
    
    try:
        # Update invoice
        invoice = Invoice.objects.get(stripe_invoice_id=stripe_invoice_id)
        invoice.status = "unpaid"
        invoice.save()
        
        # Update subscription status
        if subscription_id and invoice.subscription:
            subscription = invoice.subscription
            subscription.status = "past_due"
            subscription.save()
            
        logger.info(f"Stripe invoice payment failed: {stripe_invoice_id}")
        
    except Invoice.DoesNotExist:
        logger.warning(f"Invoice not found for Stripe invoice: {stripe_invoice_id}")


def _handle_stripe_subscription_created(subscription_data: Dict[str, Any]):
    """Handle Stripe subscription creation"""
    stripe_subscription_id = subscription_data["id"]
    customer_id = subscription_data["customer"]
    
    try:
        # Find user by Stripe customer ID
        subscription = Subscription.objects.get(
            stripe_subscription_id=stripe_subscription_id
        )
        subscription.status = subscription_data["status"]
        subscription.save()
        
        logger.info(f"Stripe subscription created: {stripe_subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for Stripe subscription: {stripe_subscription_id}")


def _handle_stripe_subscription_updated(subscription_data: Dict[str, Any]):
    """Handle Stripe subscription updates"""
    stripe_subscription_id = subscription_data["id"]
    
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=stripe_subscription_id
        )
        
        # Map Stripe status to our status
        stripe_status = subscription_data["status"]
        status_mapping = {
            "active": "active",
            "canceled": "canceled",
            "past_due": "past_due",
            "trialing": "trial",
            "unpaid": "unpaid",
            "incomplete": "unpaid",
            "incomplete_expired": "canceled"
        }
        
        subscription.status = status_mapping.get(stripe_status, "active")
        subscription.save()
        
        logger.info(f"Stripe subscription updated: {stripe_subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for Stripe subscription: {stripe_subscription_id}")


def _handle_stripe_subscription_deleted(subscription_data: Dict[str, Any]):
    """Handle Stripe subscription deletion"""
    stripe_subscription_id = subscription_data["id"]
    
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=stripe_subscription_id
        )
        subscription.status = "canceled"
        subscription.canceled_at = timezone.now()
        subscription.save()
        
        logger.info(f"Stripe subscription deleted: {stripe_subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for Stripe subscription: {stripe_subscription_id}")


def _handle_stripe_trial_will_end(subscription_data: Dict[str, Any]):
    """Handle Stripe trial ending notification"""
    stripe_subscription_id = subscription_data["id"]
    
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=stripe_subscription_id
        )
        
        # Send trial ending notification (implement as needed)
        logger.info(f"Stripe trial ending for subscription: {stripe_subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for Stripe subscription: {stripe_subscription_id}")


def _handle_stripe_customer_created(customer_data: Dict[str, Any]):
    """Handle Stripe customer creation"""
    customer_id = customer_data["id"]
    email = customer_data.get("email")
    
    if email:
        try:
            user = User.objects.get(email=email)
            # Update user's Stripe customer ID if needed
            if hasattr(user, 'subscription') and not user.subscription.stripe_customer_id:
                user.subscription.stripe_customer_id = customer_id
                user.subscription.save()
                
            logger.info(f"Stripe customer created: {customer_id} for {email}")
            
        except User.DoesNotExist:
            logger.warning(f"User not found for Stripe customer: {email}")


def _handle_stripe_customer_updated(customer_data: Dict[str, Any]):
    """Handle Stripe customer updates"""
    customer_id = customer_data["id"]
    logger.info(f"Stripe customer updated: {customer_id}")


# RazorpayX Event Handlers
def _handle_razorpay_payment_captured(payment_data: Dict[str, Any]):
    """Handle captured RazorpayX payment"""
    payment_entity = payment_data.get("payment", {}).get("entity", {})
    payment_id = payment_entity.get("id")
    amount = Decimal(payment_entity.get("amount", 0)) / 100  # Convert from paise
    
    try:
        # Find payment by RazorpayX payment ID (you'll need to add this field)
        payment = Payment.objects.get(razorpay_payment_id=payment_id)
        payment.status = "succeeded"
        payment.processed_at = timezone.now()
        payment.save()
        
        logger.info(f"RazorpayX payment captured: {payment_id}")
        
    except Payment.DoesNotExist:
        logger.warning(f"Payment not found for RazorpayX payment: {payment_id}")


def _handle_razorpay_payment_failed(payment_data: Dict[str, Any]):
    """Handle failed RazorpayX payment"""
    payment_entity = payment_data.get("payment", {}).get("entity", {})
    payment_id = payment_entity.get("id")
    error_code = payment_entity.get("error_code")
    error_description = payment_entity.get("error_description")
    
    try:
        payment = Payment.objects.get(razorpay_payment_id=payment_id)
        payment.status = "failed"
        payment.failure_code = error_code
        payment.failure_message = error_description
        payment.processed_at = timezone.now()
        payment.save()
        
        logger.info(f"RazorpayX payment failed: {payment_id} - {error_description}")
        
    except Payment.DoesNotExist:
        logger.warning(f"Payment not found for RazorpayX payment: {payment_id}")


def _handle_razorpay_payment_authorized(payment_data: Dict[str, Any]):
    """Handle authorized RazorpayX payment"""
    payment_entity = payment_data.get("payment", {}).get("entity", {})
    payment_id = payment_entity.get("id")
    
    try:
        payment = Payment.objects.get(razorpay_payment_id=payment_id)
        payment.status = "processing"
        payment.save()
        
        logger.info(f"RazorpayX payment authorized: {payment_id}")
        
    except Payment.DoesNotExist:
        logger.warning(f"Payment not found for RazorpayX payment: {payment_id}")


def _handle_razorpay_subscription_activated(subscription_data: Dict[str, Any]):
    """Handle RazorpayX subscription activation"""
    subscription_entity = subscription_data.get("subscription", {}).get("entity", {})
    subscription_id = subscription_entity.get("id")
    
    try:
        subscription = Subscription.objects.get(
            razorpay_subscription_id=subscription_id
        )
        subscription.status = "active"
        subscription.save()
        
        logger.info(f"RazorpayX subscription activated: {subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for RazorpayX subscription: {subscription_id}")


def _handle_razorpay_subscription_charged(subscription_data: Dict[str, Any]):
    """Handle RazorpayX subscription charge"""
    subscription_entity = subscription_data.get("subscription", {}).get("entity", {})
    subscription_id = subscription_entity.get("id")
    
    try:
        subscription = Subscription.objects.get(
            razorpay_subscription_id=subscription_id
        )
        subscription.status = "active"
        subscription.save()
        
        # Reset subscription credits
        subscription.reset_period_credits()
        
        logger.info(f"RazorpayX subscription charged: {subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for RazorpayX subscription: {subscription_id}")


def _handle_razorpay_subscription_cancelled(subscription_data: Dict[str, Any]):
    """Handle RazorpayX subscription cancellation"""
    subscription_entity = subscription_data.get("subscription", {}).get("entity", {})
    subscription_id = subscription_entity.get("id")
    
    try:
        subscription = Subscription.objects.get(
            razorpay_subscription_id=subscription_id
        )
        subscription.status = "canceled"
        subscription.canceled_at = timezone.now()
        subscription.save()
        
        logger.info(f"RazorpayX subscription cancelled: {subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for RazorpayX subscription: {subscription_id}")


def _handle_razorpay_subscription_completed(subscription_data: Dict[str, Any]):
    """Handle RazorpayX subscription completion"""
    subscription_entity = subscription_data.get("subscription", {}).get("entity", {})
    subscription_id = subscription_entity.get("id")
    
    try:
        subscription = Subscription.objects.get(
            razorpay_subscription_id=subscription_id
        )
        subscription.status = "completed"
        subscription.save()
        
        logger.info(f"RazorpayX subscription completed: {subscription_id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for RazorpayX subscription: {subscription_id}")


def _handle_razorpay_refund_created(refund_data: Dict[str, Any]):
    """Handle RazorpayX refund creation"""
    refund_entity = refund_data.get("refund", {}).get("entity", {})
    payment_id = refund_entity.get("payment_id")
    refund_amount = Decimal(refund_entity.get("amount", 0)) / 100
    
    try:
        payment = Payment.objects.get(razorpay_payment_id=payment_id)
        payment.status = "refunded"
        payment.save()
        
        logger.info(f"RazorpayX refund created for payment: {payment_id}")
        
    except Payment.DoesNotExist:
        logger.warning(f"Payment not found for RazorpayX refund: {payment_id}")


def _verify_razorpay_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify RazorpayX webhook signature"""
    if not signature or not secret:
        return False
        
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)