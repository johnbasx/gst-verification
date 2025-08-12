# Billing App

The Billing app handles subscription management, payment processing, invoice generation, and financial operations for the GST SaaS platform. It integrates with Stripe for secure payment processing and provides comprehensive billing analytics.

## Features

- **Subscription Management**: Multiple subscription plans with different features
- **Payment Processing**: Secure payments via Stripe integration
- **Invoice Generation**: Automated invoice creation and management
- **Credit System**: Credit-based usage tracking and billing
- **Discount Management**: Coupon codes and promotional discounts
- **Webhook Handling**: Real-time Stripe webhook processing
- **Billing Analytics**: Comprehensive financial reporting
- **Tax Calculation**: Automated tax computation
- **Recurring Billing**: Automated subscription renewals

## Models

### SubscriptionPlan
Defines available subscription tiers:
- `name`, `description`
- `price` (monthly price)
- `billing_cycle` (monthly/yearly)
- `features` (JSON field with plan features)
- `api_calls_limit` (monthly API call limit)
- `credits_included` (monthly credits)
- `is_active`, `is_popular`
- `stripe_price_id`
- `created_at`, `updated_at`

### UserSubscription
Tracks user subscription status:
- `user` (OneToOne to User)
- `plan` (ForeignKey to SubscriptionPlan)
- `status` (active/canceled/past_due/trialing)
- `current_period_start`, `current_period_end`
- `stripe_subscription_id`
- `stripe_customer_id`
- `cancel_at_period_end`
- `trial_end`
- `created_at`, `updated_at`

### Invoice
Stores billing invoices:
- `user` (ForeignKey to User)
- `subscription` (ForeignKey to UserSubscription)
- `invoice_number` (unique identifier)
- `amount`, `tax_amount`, `total_amount`
- `currency` (default: INR)
- `status` (draft/sent/paid/overdue/void)
- `due_date`, `paid_date`
- `stripe_invoice_id`
- `invoice_pdf` (file field)
- `created_at`, `updated_at`

### Payment
Tracks payment transactions:
- `user` (ForeignKey to User)
- `invoice` (ForeignKey to Invoice)
- `amount`, `currency`
- `payment_method` (card/bank_transfer/wallet)
- `status` (pending/completed/failed/refunded)
- `stripe_payment_intent_id`
- `transaction_id`
- `payment_date`
- `failure_reason`
- `created_at`, `updated_at`

### Discount
Manages promotional discounts:
- `code` (unique coupon code)
- `name`, `description`
- `discount_type` (percentage/fixed_amount)
- `discount_value`
- `minimum_amount` (minimum order value)
- `usage_limit`, `used_count`
- `valid_from`, `valid_until`
- `is_active`
- `applicable_plans` (ManyToMany to SubscriptionPlan)
- `created_at`, `updated_at`

## API Endpoints

### Subscription Plans
- `GET /api/billing/plans/` - List all subscription plans

### User Subscription
- `GET /api/billing/subscription/` - Get current subscription
- `POST /api/billing/subscription/` - Create new subscription
- `PUT /api/billing/subscription/` - Update subscription
- `DELETE /api/billing/subscription/cancel/` - Cancel subscription

### Invoices
- `GET /api/billing/invoices/` - List user invoices
- `GET /api/billing/invoices/{id}/` - Get invoice details
- `GET /api/billing/invoices/{id}/download/` - Download invoice PDF

### Payments
- `POST /api/billing/payments/` - Create payment intent
- `GET /api/billing/payments/{id}/` - Get payment status

### Discounts
- `POST /api/billing/discounts/validate/` - Validate discount code

### Analytics
- `GET /api/billing/stats/` - Get billing statistics

### Webhooks
- `POST /api/billing/webhooks/stripe/` - Stripe webhook endpoint

## Serializers

### SubscriptionPlanSerializer
Handles subscription plan data:
```python
{
    "id": 1,
    "name": "Professional",
    "description": "Perfect for growing businesses",
    "price": "999.00",
    "billing_cycle": "monthly",
    "features": {
        "api_calls": 10000,
        "bulk_verification": true,
        "priority_support": true,
        "custom_integrations": false
    },
    "api_calls_limit": 10000,
    "credits_included": 1000,
    "is_popular": true
}
```

### SubscriptionCreateSerializer
Handles subscription creation:
```python
{
    "plan_id": 1,
    "payment_method_id": "pm_1234567890",
    "discount_code": "WELCOME20",
    "billing_address": {
        "line1": "123 Business Street",
        "city": "Bangalore",
        "state": "Karnataka",
        "postal_code": "560001",
        "country": "IN"
    }
}
```

### InvoiceSerializer
Handles invoice data:
```python
{
    "id": 1,
    "invoice_number": "INV-2024-001",
    "amount": "999.00",
    "tax_amount": "179.82",
    "total_amount": "1178.82",
    "currency": "INR",
    "status": "paid",
    "due_date": "2024-02-15",
    "paid_date": "2024-01-16",
    "created_at": "2024-01-15T10:30:00Z"
}
```

### PaymentCreateSerializer
Handles payment creation:
```python
{
    "amount": "1178.82",
    "currency": "INR",
    "payment_method_id": "pm_1234567890",
    "invoice_id": 1,
    "save_payment_method": true
}
```

## Views

### SubscriptionPlanListView
- Lists all active subscription plans
- Shows features and pricing
- Public endpoint (no authentication required)

### UserSubscriptionView
- Handles subscription CRUD operations
- Integrates with Stripe for payment processing
- Manages subscription lifecycle

### InvoiceListView & InvoiceDetailView
- Manages invoice operations
- Generates PDF invoices
- Handles invoice status updates

### PaymentCreateView
- Creates Stripe payment intents
- Handles payment confirmation
- Updates payment status

### DiscountValidationView
- Validates discount codes
- Checks usage limits and validity
- Calculates discount amounts

## Stripe Integration

### Webhook Events Handled
```python
WEBHOOK_EVENTS = {
    'customer.subscription.created': handle_subscription_created,
    'customer.subscription.updated': handle_subscription_updated,
    'customer.subscription.deleted': handle_subscription_deleted,
    'invoice.payment_succeeded': handle_payment_succeeded,
    'invoice.payment_failed': handle_payment_failed,
    'customer.created': handle_customer_created,
    'payment_intent.succeeded': handle_payment_succeeded,
    'payment_intent.payment_failed': handle_payment_failed,
}
```

### Subscription Creation Flow
```python
def create_stripe_subscription(user, plan, payment_method_id):
    """Create Stripe subscription"""
    # Create or get Stripe customer
    customer = get_or_create_stripe_customer(user)
    
    # Attach payment method
    stripe.PaymentMethod.attach(
        payment_method_id,
        customer=customer.id
    )
    
    # Create subscription
    subscription = stripe.Subscription.create(
        customer=customer.id,
        items=[{'price': plan.stripe_price_id}],
        default_payment_method=payment_method_id,
        expand=['latest_invoice.payment_intent']
    )
    
    return subscription
```

## Subscription Plans

### Free Plan
```json
{
    "name": "Free",
    "price": "0.00",
    "features": {
        "api_calls": 100,
        "gstin_validation": true,
        "basic_verification": false,
        "bulk_verification": false,
        "priority_support": false
    },
    "credits_included": 10
}
```

### Starter Plan
```json
{
    "name": "Starter",
    "price": "499.00",
    "features": {
        "api_calls": 1000,
        "gstin_validation": true,
        "basic_verification": true,
        "bulk_verification": false,
        "priority_support": false
    },
    "credits_included": 100
}
```

### Professional Plan
```json
{
    "name": "Professional",
    "price": "999.00",
    "features": {
        "api_calls": 10000,
        "gstin_validation": true,
        "basic_verification": true,
        "bulk_verification": true,
        "priority_support": true,
        "custom_integrations": false
    },
    "credits_included": 1000
}
```

### Enterprise Plan
```json
{
    "name": "Enterprise",
    "price": "2999.00",
    "features": {
        "api_calls": "unlimited",
        "gstin_validation": true,
        "basic_verification": true,
        "bulk_verification": true,
        "priority_support": true,
        "custom_integrations": true,
        "dedicated_support": true
    },
    "credits_included": 5000
}
```

## Invoice Generation

### PDF Invoice Template
```python
def generate_invoice_pdf(invoice):
    """Generate PDF invoice"""
    template = get_template('billing/invoice_template.html')
    context = {
        'invoice': invoice,
        'user': invoice.user,
        'subscription': invoice.subscription,
        'company_info': get_company_info(),
    }
    
    html = template.render(context)
    pdf = weasyprint.HTML(string=html).write_pdf()
    
    # Save PDF to invoice
    invoice.invoice_pdf.save(
        f'invoice_{invoice.invoice_number}.pdf',
        ContentFile(pdf)
    )
```

### Invoice Number Generation
```python
def generate_invoice_number():
    """Generate unique invoice number"""
    current_year = timezone.now().year
    current_month = timezone.now().month
    
    # Get last invoice number for current month
    last_invoice = Invoice.objects.filter(
        created_at__year=current_year,
        created_at__month=current_month
    ).order_by('-id').first()
    
    if last_invoice:
        last_number = int(last_invoice.invoice_number.split('-')[-1])
        next_number = last_number + 1
    else:
        next_number = 1
    
    return f"INV-{current_year}-{current_month:02d}-{next_number:04d}"
```

## Tax Calculation

### Indian GST Calculation
```python
def calculate_gst(amount, gst_rate=18):
    """Calculate GST for Indian customers"""
    gst_amount = (amount * gst_rate) / 100
    return {
        'base_amount': amount,
        'gst_rate': gst_rate,
        'gst_amount': gst_amount,
        'total_amount': amount + gst_amount
    }

def get_applicable_tax_rate(user_location, plan):
    """Get applicable tax rate based on location"""
    if user_location.country == 'IN':
        return 18  # GST rate for digital services
    else:
        return 0   # No tax for international customers
```

## Usage Examples

### Get Subscription Plans
```bash
curl -X GET http://localhost:8000/api/billing/plans/
```

### Create Subscription
```bash
curl -X POST http://localhost:8000/api/billing/subscription/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan_id": 2,
    "payment_method_id": "pm_1234567890",
    "discount_code": "WELCOME20"
  }'
```

### Validate Discount Code
```bash
curl -X POST http://localhost:8000/api/billing/discounts/validate/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "WELCOME20",
    "plan_id": 2
  }'
```

### Create Payment
```bash
curl -X POST http://localhost:8000/api/billing/payments/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": "1178.82",
    "currency": "INR",
    "payment_method_id": "pm_1234567890"
  }'
```

## Error Handling

### Common Error Responses
```json
{
    "error": "payment_failed",
    "message": "Payment could not be processed",
    "details": {
        "payment_intent_id": "pi_1234567890",
        "failure_code": "card_declined",
        "failure_message": "Your card was declined."
    }
}
```

### Error Codes
- `invalid_plan`: Subscription plan not found or inactive
- `payment_failed`: Payment processing failed
- `insufficient_funds`: Insufficient account balance
- `invalid_discount`: Discount code invalid or expired
- `subscription_exists`: User already has active subscription
- `webhook_verification_failed`: Stripe webhook verification failed

## Billing Analytics

### Revenue Metrics
```python
def get_revenue_metrics(start_date, end_date):
    """Get revenue analytics"""
    return {
        'total_revenue': get_total_revenue(start_date, end_date),
        'monthly_recurring_revenue': get_mrr(),
        'annual_recurring_revenue': get_arr(),
        'average_revenue_per_user': get_arpu(),
        'customer_lifetime_value': get_clv(),
        'churn_rate': get_churn_rate(),
        'subscription_growth': get_subscription_growth()
    }
```

### Key Performance Indicators
- **MRR (Monthly Recurring Revenue)**: Predictable monthly revenue
- **ARR (Annual Recurring Revenue)**: Yearly recurring revenue
- **ARPU (Average Revenue Per User)**: Revenue per customer
- **CLV (Customer Lifetime Value)**: Total customer value
- **Churn Rate**: Customer cancellation rate
- **Conversion Rate**: Trial to paid conversion

## Security Features

- **PCI Compliance**: Stripe handles sensitive payment data
- **Webhook Verification**: Stripe webhook signature verification
- **Secure Payment Processing**: No card data stored locally
- **Fraud Detection**: Stripe Radar integration
- **Data Encryption**: Sensitive billing data encryption

## Configuration

Add to Django settings:
```python
# Stripe Settings
STRIPE_PUBLISHABLE_KEY = 'pk_test_...'
STRIPE_SECRET_KEY = 'sk_test_...'
STRIPE_WEBHOOK_SECRET = 'whsec_...'

# Billing Settings
BILLING = {
    'DEFAULT_CURRENCY': 'INR',
    'TAX_RATE': 18,  # GST rate for India
    'INVOICE_PREFIX': 'INV',
    'PAYMENT_METHODS': ['card', 'bank_transfer'],
    'TRIAL_PERIOD_DAYS': 14,
    'GRACE_PERIOD_DAYS': 3,
}

# Email Settings for Invoices
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
```

## Testing

### Stripe Test Mode
Use Stripe test keys and test card numbers:
```python
TEST_CARDS = {
    'visa': '4242424242424242',
    'visa_debit': '4000056655665556',
    'mastercard': '5555555555554444',
    'declined': '4000000000000002',
}
```

### Mock Webhook Testing
```bash
# Install Stripe CLI
stripe listen --forward-to localhost:8000/api/billing/webhooks/stripe/

# Trigger test events
stripe trigger customer.subscription.created
stripe trigger invoice.payment_succeeded
```

### Run Tests
```bash
python manage.py test billing
```

## Dependencies

- Django REST Framework
- stripe (payment processing)
- weasyprint (PDF generation)
- celery (background tasks)
- redis (caching and task queue)
- drf-spectacular (API documentation)

## Admin Interface

The app includes admin configurations for:
- Subscription plan management
- User subscription monitoring
- Invoice and payment tracking
- Discount code management
- Revenue analytics dashboard

## Background Tasks

### Celery Tasks
```python
@shared_task
def send_invoice_email(invoice_id):
    """Send invoice via email"""
    invoice = Invoice.objects.get(id=invoice_id)
    send_mail(
        subject=f'Invoice {invoice.invoice_number}',
        message='Please find your invoice attached.',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[invoice.user.email],
        attachments=[(f'invoice_{invoice.invoice_number}.pdf', 
                     invoice.invoice_pdf.read(), 'application/pdf')]
    )

@shared_task
def process_failed_payments():
    """Retry failed payments"""
    failed_payments = Payment.objects.filter(
        status='failed',
        created_at__gte=timezone.now() - timedelta(days=3)
    )
    
    for payment in failed_payments:
        retry_payment(payment)
```

## Monitoring & Alerts

### Key Metrics to Monitor
- Payment success/failure rates
- Subscription churn rate
- Revenue trends
- Failed webhook deliveries
- Invoice generation errors

### Health Checks
```python
@api_view(['GET'])
def billing_health_check(request):
    """Billing system health check"""
    return Response({
        'status': 'healthy',
        'stripe_connection': check_stripe_connection(),
        'database': check_database_connection(),
        'webhook_status': check_webhook_status(),
        'timestamp': timezone.now()
    })
```