from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from api_management.models import PaymentMethod, ReferralProgram
from django.utils import timezone
from datetime import timedelta

User = get_user_model()


class Command(BaseCommand):
    help = 'Populate sample data for new API management features'

    def handle(self, *args, **options):
        self.stdout.write('Creating sample payment methods...')
        
        # Create payment methods for different countries
        payment_methods = [
            {
                'country_code': 'US',
                'country_name': 'United States',
                'provider': 'stripe',
                'currency': 'USD',
                'currency_symbol': '$',
                'is_active': True,
                'is_default': True,
            },
            {
                'country_code': 'IN',
                'country_name': 'India',
                'provider': 'razorpay',
                'currency': 'INR',
                'currency_symbol': '₹',
                'is_active': True,
                'is_default': False,
            },
            {
                'country_code': 'GB',
                'country_name': 'United Kingdom',
                'provider': 'stripe',
                'currency': 'GBP',
                'currency_symbol': '£',
                'is_active': True,
                'is_default': False,
            },
            {
                'country_code': 'CA',
                'country_name': 'Canada',
                'provider': 'stripe',
                'currency': 'CAD',
                'currency_symbol': 'C$',
                'is_active': True,
                'is_default': False,
            },
            {
                'country_code': 'AU',
                'country_name': 'Australia',
                'provider': 'stripe',
                'currency': 'AUD',
                'currency_symbol': 'A$',
                'is_active': True,
                'is_default': False,
            },
        ]
        
        for method_data in payment_methods:
            payment_method, created = PaymentMethod.objects.get_or_create(
                country_code=method_data['country_code'],
                provider=method_data['provider'],
                defaults=method_data
            )
            if created:
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Created payment method: {method_data["country_name"]} - {method_data["provider"]}'
                    )
                )
            else:
                self.stdout.write(
                    f'Payment method already exists: {method_data["country_name"]} - {method_data["provider"]}'
                )
        
        # Create sample referral programs for existing users
        self.stdout.write('Creating sample referral programs...')
        
        users = list(User.objects.all()[:4])  # Get first 4 users
        if len(users) >= 2:
            # Create referral relationships between users
            for i in range(0, len(users) - 1, 2):
                referrer = users[i]
                referred = users[i + 1]
                
                referral, created = ReferralProgram.objects.get_or_create(
                    referrer=referrer,
                    referred_user=referred,
                    defaults={
                        'referrer_bonus_credits': 100.0,
                        'referred_bonus_credits': 50.0,
                        'status': 'pending',
                        'expires_at': timezone.now() + timedelta(days=365),
                    }
                )
                if created:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'Created referral: {referrer.email} -> {referred.email} with code: {referral.referral_code}'
                        )
                    )
                else:
                    self.stdout.write(
                        f'Referral already exists: {referrer.email} -> {referred.email}'
                    )
        else:
            self.stdout.write(
                self.style.WARNING('Need at least 2 users to create referral relationships')
            )
        
        self.stdout.write(
            self.style.SUCCESS('Successfully populated sample data!')
        )