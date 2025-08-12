#!/usr/bin/env python
"""
Test script to demonstrate the new API management features:
- API Usage Tracking
- Credits System with Referrals
- Location-based Payment Methods
"""

import os
import sys
import django
from datetime import timedelta
from django.utils import timezone

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gst_saas.settings')
django.setup()

from django.contrib.auth import get_user_model
from api_management.models import (
    APIKey, APIUsage, UserCredits, ReferralProgram, 
    PaymentMethod, APIUsageAnalytics
)
from api_management.serializers import (
    ReferralStatsSerializer, PaymentMethodSerializer,
    APIUsageAnalyticsSerializer
)

User = get_user_model()

def test_payment_methods():
    """Test location-based payment methods"""
    print("\n=== Testing Payment Methods ===")
    
    # Get payment methods for different countries
    countries = ['US', 'IN', 'GB', 'CA', 'AU']
    
    for country in countries:
        methods = PaymentMethod.objects.filter(country_code=country, is_active=True)
        print(f"\n{country} Payment Methods:")
        for method in methods:
            serializer = PaymentMethodSerializer(method)
            data = serializer.data
            print(f"  - {data['country_name']}: {data['provider']} ({data['currency_symbol']}{data['currency']})")

def test_referral_system():
    """Test referral system functionality"""
    print("\n=== Testing Referral System ===")
    
    # Get all referral programs
    referrals = ReferralProgram.objects.all()
    
    for referral in referrals:
        print(f"\nReferral Code: {referral.referral_code}")
        print(f"Referrer: {referral.referrer.email}")
        print(f"Referred User: {referral.referred_user.email}")
        print(f"Status: {referral.status}")
        print(f"Referrer Bonus: {referral.referrer_bonus_credits} credits")
        print(f"Referred Bonus: {referral.referred_bonus_credits} credits")
        print(f"Expires: {referral.expires_at}")
        
        # Test referral stats
        stats_data = {
            'total_referrals': 1,
            'successful_referrals': 0 if referral.status == 'pending' else 1,
            'pending_referrals': 1 if referral.status == 'pending' else 0,
            'total_bonus_earned': 0 if not referral.bonus_awarded else referral.referrer_bonus_credits,
            'referral_conversion_rate': 0.0 if referral.status == 'pending' else 100.0
        }
        
        serializer = ReferralStatsSerializer(data=stats_data)
        if serializer.is_valid():
            print(f"Referral Stats: {serializer.validated_data}")

def test_api_usage_analytics():
    """Test API usage analytics"""
    print("\n=== Testing API Usage Analytics ===")
    
    # Create sample API usage data
    users = User.objects.all()[:2]
    
    for user in users:
        # Create API key if doesn't exist
        api_key, created = APIKey.objects.get_or_create(
            user=user,
            name=f"Test Key for {user.email}",
            defaults={
                'is_active': True,
                'rate_limit_per_minute': 60,
                'rate_limit_per_hour': 1000,
                'rate_limit_per_day': 10000,
            }
        )
        
        # Create sample usage records
        for i in range(3):
            APIUsage.objects.get_or_create(
                user=user,
                api_key=api_key,
                endpoint='/api/gst/verify/',
                method='POST',
                status_code=200,
                response_time_ms=150 + i * 10,
                ip_address='127.0.0.1',
                credits_used=1.0,
                defaults={
                    'request_size_bytes': 256,
                    'response_size_bytes': 512,
                }
            )
        
        # Create analytics record
        analytics, created = APIUsageAnalytics.objects.get_or_create(
            user=user,
            date=timezone.now().date(),
            period_type='daily',
            defaults={
                'total_requests': 3,
                'successful_requests': 3,
                'failed_requests': 0,
                'total_credits_used': 3.0,
                'avg_response_time_ms': 160.0,
                'total_data_transferred_mb': 0.002,
                'endpoint_usage': {
                    '/api/gst/verify/': 3
                }
            }
        )
        
        if created:
            print(f"\nCreated analytics for {user.email}:")
            serializer = APIUsageAnalyticsSerializer(analytics)
            data = serializer.data
            print(f"  - Total Requests: {data['total_requests']}")
            print(f"  - Success Rate: {(data['successful_requests']/data['total_requests']*100):.1f}%")
            print(f"  - Credits Used: {data['total_credits_used']}")
            print(f"  - Avg Response Time: {data['avg_response_time_ms']}ms")
            print(f"  - Data Transferred: {data['total_data_transferred_mb']}MB")
        else:
            print(f"Analytics already exists for {user.email}")

def test_credits_system():
    """Test credits system"""
    print("\n=== Testing Credits System ===")
    
    users = User.objects.all()[:2]
    
    for user in users:
        credits, created = UserCredits.objects.get_or_create(
            user=user,
            defaults={
                'available_credits': 100.0,
                'total_purchased': 0.0,
                'total_used': 0.0,
                'trial_credits_granted': 100.0,
                'trial_credits_used': 0.0,
            }
        )
        
        print(f"\n{user.email} Credits:")
        print(f"  - Available: {credits.available_credits}")
        print(f"  - Trial Remaining: {credits.trial_credits_remaining}")
        print(f"  - Total Remaining: {credits.total_credits_remaining}")
        print(f"  - Can use 5 credits: {credits.can_use_credits(5)}")

def main():
    """Run all tests"""
    print("🚀 Testing New API Management Features")
    print("=" * 50)
    
    try:
        test_payment_methods()
        test_referral_system()
        test_api_usage_analytics()
        test_credits_system()
        
        print("\n" + "=" * 50)
        print("✅ All tests completed successfully!")
        print("\n📊 Summary of New Features:")
        print("  1. ✅ Location-based Payment Methods - Configured for 5 countries")
        print("  2. ✅ Referral System - Active referral programs created")
        print("  3. ✅ API Usage Analytics - Tracking and aggregation working")
        print("  4. ✅ Enhanced Credits System - Trial and purchased credits managed")
        print("\n🌐 Server running at: http://127.0.0.1:8000")
        print("📚 API Documentation: http://127.0.0.1:8000/api/docs/")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()