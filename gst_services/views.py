import time
import uuid
from datetime import datetime, timedelta

import requests
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from api_management.models import APIKey, APIUsage, UserCredits
from authentication.models import UserActivity

from .models import GSTRequest, GSTService, GSTVerificationResult
from .serializers import (
    BulkGSTVerificationResponseSerializer,
    BulkGSTVerificationSerializer,
    GSTComplianceResponseSerializer,
    GSTComplianceSerializer,
    GSTDetailsSerializer,
    GSTINValidationSerializer,
    GSTSearchResultSerializer,
    GSTSearchSerializer,
    GSTServiceSerializer,
    GSTVerificationRequestSerializer,
    GSTVerificationResponseSerializer,
    GSTVerificationSerializer,
)


class GSTServiceListView(generics.ListAPIView):
    """List available GST services"""

    serializer_class = GSTServiceSerializer
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="List GST services",
        description="Get list of available GST verification services",
        tags=["GST Services"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return GSTService.objects.filter(is_active=True).order_by("name")


class GSTINValidationView(APIView):
    """GSTIN format validation endpoint"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Validate GSTIN format",
        description="Validate GSTIN format and checksum without consuming credits",
        request=GSTINValidationSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "gstin": {"type": "string"},
                    "is_valid": {"type": "boolean"},
                    "format_valid": {"type": "boolean"},
                    "checksum_valid": {"type": "boolean"},
                    "state_code": {"type": "string"},
                    "state_name": {"type": "string"},
                    "entity_code": {"type": "string"},
                    "message": {"type": "string"},
                },
            }
        },
        tags=["GST Services"],
    )
    def post(self, request):
        serializer = GSTINValidationSerializer(data=request.data)

        if serializer.is_valid():
            gstin = serializer.validated_data["gstin"]

            # Log user activity
            UserActivity.objects.create(
                user=request.user,
                activity_type="gstin_validation",
                description=f"GSTIN format validation for {gstin}",
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
            )

            # Validate format and checksum
            validation_result = self._validate_gstin_comprehensive(gstin)

            return Response(validation_result, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _validate_gstin_comprehensive(self, gstin):
        """Comprehensive GSTIN validation"""
        # State codes mapping
        state_codes = {
            "01": "Jammu and Kashmir",
            "02": "Himachal Pradesh",
            "03": "Punjab",
            "04": "Chandigarh",
            "05": "Uttarakhand",
            "06": "Haryana",
            "07": "Delhi",
            "08": "Rajasthan",
            "09": "Uttar Pradesh",
            "10": "Bihar",
            "11": "Sikkim",
            "12": "Arunachal Pradesh",
            "13": "Nagaland",
            "14": "Manipur",
            "15": "Mizoram",
            "16": "Tripura",
            "17": "Meghalaya",
            "18": "Assam",
            "19": "West Bengal",
            "20": "Jharkhand",
            "21": "Odisha",
            "22": "Chhattisgarh",
            "23": "Madhya Pradesh",
            "24": "Gujarat",
            "25": "Daman and Diu",
            "26": "Dadra and Nagar Haveli",
            "27": "Maharashtra",
            "28": "Andhra Pradesh",
            "29": "Karnataka",
            "30": "Goa",
            "31": "Lakshadweep",
            "32": "Kerala",
            "33": "Tamil Nadu",
            "34": "Puducherry",
            "35": "Andaman and Nicobar Islands",
            "36": "Telangana",
            "37": "Andhra Pradesh",
            "96": "Foreign Jurisdiction",
            "97": "Other Territory",
            "99": "Centre Jurisdiction",
        }

        # Entity type codes
        entity_codes = {
            "1": "Proprietorship",
            "2": "Partnership",
            "3": "LLP",
            "4": "Private Limited Company",
            "5": "Public Limited Company",
            "6": "Government Department",
            "7": "Trust",
            "8": "Society",
            "9": "Others",
            "A": "Association of Persons",
            "B": "Body of Individuals",
            "C": "Company",
            "F": "Firm",
            "G": "Government",
            "H": "HUF",
            "L": "Local Authority",
            "P": "Person",
            "T": "Trust",
            "V": "Statutory Body",
        }

        state_code = gstin[:2]
        entity_code = gstin[12]

        # Format validation
        format_valid = len(gstin) == 15 and gstin.isalnum()

        # Checksum validation
        checksum_valid = self._validate_gstin_checksum(gstin)

        is_valid = format_valid and checksum_valid

        return {
            "gstin": gstin,
            "is_valid": is_valid,
            "format_valid": format_valid,
            "checksum_valid": checksum_valid,
            "state_code": state_code,
            "state_name": state_codes.get(state_code, "Unknown"),
            "entity_code": entity_code,
            "entity_type": entity_codes.get(entity_code, "Unknown"),
            "message": "Valid GSTIN"
            if is_valid
            else "Invalid GSTIN format or checksum",
        }

    def _validate_gstin_checksum(self, gstin):
        """Validate GSTIN checksum"""
        try:
            factor = 2
            sum_val = 0
            code_point_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

            for i in range(14):
                code_point = code_point_chars.index(gstin[i])
                digit = factor * code_point
                factor = 1 if factor == 2 else 2
                digit = (digit // 36) + (digit % 36)
                sum_val += digit

            remainder = sum_val % 36
            check_code_point = (36 - remainder) % 36

            return gstin[14] == code_point_chars[check_code_point]
        except (ValueError, IndexError):
            return False

    def _get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class GSTVerificationView(APIView):
    """GST verification endpoint"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Verify GST details",
        description="Verify GST details and get business information",
        request=GSTVerificationSerializer,
        responses={200: GSTDetailsSerializer},
        tags=["GST Services"],
    )
    def post(self, request):
        # Validate API key from header
        api_key = self._get_api_key_from_header(request)
        if not api_key:
            return Response(
                {"error": "API key required in Authorization header"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Check if API key belongs to user
        if api_key.user != request.user:
            return Response(
                {"error": "Invalid API key"}, status=status.HTTP_403_FORBIDDEN
            )

        # Check if API key is active
        if not api_key.is_active:
            return Response(
                {"error": "API key is inactive"}, status=status.HTTP_403_FORBIDDEN
            )

        serializer = GSTVerificationSerializer(data=request.data)

        if serializer.is_valid():
            gstin = serializer.validated_data["gstin"]
            include_details = serializer.validated_data["include_details"]

            # Get GST service
            try:
                service = GSTService.objects.get(
                    name="GST Verification", is_active=True
                )
            except GSTService.DoesNotExist:
                return Response(
                    {"error": "GST verification service not available"},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            # Check user credits
            user_credits = UserCredits.objects.filter(user=request.user).first()
            if (
                not user_credits
                or user_credits.available_credits < service.credits_required
            ):
                return Response(
                    {
                        "error": "Insufficient credits",
                        "required_credits": service.credits_required,
                        "available_credits": user_credits.available_credits
                        if user_credits
                        else 0,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED,
                )

            # Create verification request
            gst_request = GSTRequest.objects.create(
                user=request.user,
                api_key=api_key,
                service=service,
                endpoint=request.path,
                request_body=request.data,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
                status="processing",
            )

            start_time = time.time()

            try:
                # Check cache first
                cache_key = f"gst_verification_{gstin}_{include_details}"
                cached_result = cache.get(cache_key)

                if cached_result:
                    response_data = cached_result
                    response_time_ms = int((time.time() - start_time) * 1000)
                else:
                    # Perform GST verification
                    response_data = self._verify_gst_details(gstin, include_details)
                    response_time_ms = int((time.time() - start_time) * 1000)

                    # Cache result for 1 hour
                    cache.set(cache_key, response_data, 3600)

                # Create verification result
                GSTVerificationResult.objects.create(
                    request=gst_request,
                    gstin=gstin,
                    legal_name=response_data.get("legal_name", ""),
                    trade_name=response_data.get("trade_name", ""),
                    status=response_data.get("status", "unknown").lower(),
                    is_verified=response_data.get("is_active", False),
                    additional_data=response_data,
                )

                # Update request status
                gst_request.status = "success"
                gst_request.response_body = response_data
                gst_request.response_time_ms = response_time_ms
                gst_request.credits_consumed = service.credits_required
                gst_request.save()

                # Deduct credits
                user_credits.available_credits -= service.credits_required
                user_credits.total_used += service.credits_required
                user_credits.save()

                # Update API key usage
                api_key.total_requests += 1
                api_key.last_used_at = timezone.now()
                api_key.save()

                # Log API usage
                APIUsage.objects.create(
                    user=request.user,
                    api_key=api_key,
                    service=service,
                    endpoint=request.path,
                    method=request.method,
                    status_code=200,
                    response_time_ms=response_time_ms,
                    credits_used=service.credits_required,
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
                )

                # Log user activity
                UserActivity.objects.create(
                    user=request.user,
                    activity_type="gst_verification",
                    description=f"GST verification for {gstin}",
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
                )

                return Response(response_data, status=status.HTTP_200_OK)

            except Exception as e:
                # Handle verification error
                error_message = str(e)
                response_time_ms = int((time.time() - start_time) * 1000)

                # Update request with error
                gst_request.status = "error"
                gst_request.error_message = error_message
                gst_request.response_time_ms = response_time_ms
                gst_request.save()

                return Response(
                    {"error": "Verification failed", "details": error_message},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _verify_gst_details(self, gstin, include_details=True):
        """Mock GST verification - replace with actual API integration"""
        # This is a mock implementation
        # In production, integrate with actual GST verification APIs

        import random
        from datetime import date

        # Simulate API delay
        time.sleep(0.5)

        # Mock business names based on GSTIN
        business_names = [
            "ABC Private Limited",
            "XYZ Industries",
            "Tech Solutions Pvt Ltd",
            "Global Trading Company",
            "Innovation Hub LLP",
            "Digital Services Ltd",
        ]

        mock_data = {
            "gstin": gstin,
            "legal_name": random.choice(business_names),
            "trade_name": random.choice(business_names)
            if random.choice([True, False])
            else "",
            "registration_date": date(
                2018, random.randint(1, 12), random.randint(1, 28)
            ),
            "constitution_of_business": random.choice(
                ["Private Limited Company", "Partnership", "Proprietorship"]
            ),
            "taxpayer_type": "Regular",
            "status": random.choice(["Active", "Cancelled", "Suspended"]),
            "principal_place_address": {
                "building_name": "Business Tower",
                "street": "Main Street",
                "city": "Mumbai",
                "state": "Maharashtra",
                "pincode": "400001",
            },
            "verification_date": timezone.now(),
            "data_source": "GST Portal",
            "is_active": True,
        }

        if include_details:
            mock_data.update(
                {
                    "additional_places_of_business": [],
                    "nature_of_business_activities": ["Trading", "Services"],
                    "filing_status": [
                        {
                            "return_type": "GSTR-1",
                            "period": "03-2024",
                            "status": "Filed",
                            "filed_date": "2024-04-10",
                        }
                    ],
                }
            )

        return mock_data

    def _get_api_key_from_header(self, request):
        """Extract API key from Authorization header"""
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        api_key_string = auth_header[7:]  # Remove 'Bearer ' prefix

        try:
            key_id, key_secret = api_key_string.split(".", 1)
            api_key = APIKey.objects.get(key_id=key_id, key_secret=key_secret)
            return api_key
        except (ValueError, APIKey.DoesNotExist):
            return None

    def _get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class GSTComplianceCheckView(APIView):
    """GST compliance check endpoint"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Check GST compliance",
        description="Check GST filing compliance for a specific period",
        request=GSTComplianceSerializer,
        responses={200: GSTComplianceResponseSerializer},
        tags=["GST Services"],
    )
    def post(self, request):
        # Similar structure to GSTVerificationView
        # Implementation would check GST return filing status
        serializer = GSTComplianceSerializer(data=request.data)

        if serializer.is_valid():
            gstin = serializer.validated_data["gstin"]
            period = serializer.validated_data["check_period"]

            # Mock compliance data
            compliance_data = {
                "gstin": gstin,
                "period": period,
                "filing_status": "Filed",
                "return_type": "GSTR-1",
                "due_date": "2024-04-11",
                "filed_date": "2024-04-10",
                "is_compliant": True,
                "penalty_amount": None,
            }

            return Response(compliance_data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GSTSearchView(APIView):
    """GST search endpoint"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Search GST records",
        description="Search GST records by business name, GSTIN, or PAN",
        request=GSTSearchSerializer,
        responses={200: GSTSearchResultSerializer(many=True)},
        tags=["GST Services"],
    )
    def post(self, request):
        serializer = GSTSearchSerializer(data=request.data)

        if serializer.is_valid():
            query = serializer.validated_data["query"]
            search_type = serializer.validated_data["search_type"]
            limit = serializer.validated_data["limit"]

            # Mock search results based on query and search_type
            mock_results = [
                {
                    "gstin": "22AAAAA0000A1Z5",
                    "legal_name": f"Search result for '{query}'",
                    "trade_name": f"Trading Company ({search_type})",
                    "status": "Active",
                    "registration_date": "2018-07-01",
                    "state_name": "Chhattisgarh",
                    "business_type": "Private Limited Company",
                    "match_score": 0.95,
                }
            ]

            return Response(mock_results[:limit], status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BulkGSTVerificationView(APIView):
    """Bulk GST verification endpoint"""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Bulk GST verification",
        description="Verify multiple GSTINs in a single request",
        request=BulkGSTVerificationSerializer,
        responses={200: BulkGSTVerificationResponseSerializer},
        tags=["GST Services"],
    )
    def post(self, request):
        serializer = BulkGSTVerificationSerializer(data=request.data)

        if serializer.is_valid():
            gstins = serializer.validated_data["gstins"]
            include_details = serializer.validated_data["include_details"]

            start_time = time.time()
            batch_id = str(uuid.uuid4())

            # Process each GSTIN
            results = []
            valid_count = 0
            invalid_count = 0

            for gstin in gstins:
                try:
                    # Mock verification for each GSTIN
                    result = {
                        "gstin": gstin,
                        "is_valid": True,
                        "status": "Active",
                        "legal_name": f"Business for {gstin}",
                    }

                    if include_details:
                        result.update(
                            {
                                "registration_date": "2018-07-01",
                                "business_type": "Private Limited Company",
                            }
                        )

                    results.append(result)
                    valid_count += 1

                except Exception:
                    results.append(
                        {
                            "gstin": gstin,
                            "is_valid": False,
                            "error": "Verification failed",
                        }
                    )
                    invalid_count += 1

            processing_time = int((time.time() - start_time) * 1000)
            credits_consumed = len(gstins) * 2  # 2 credits per GSTIN

            response_data = {
                "total_requested": len(gstins),
                "total_processed": len(results),
                "total_valid": valid_count,
                "total_invalid": invalid_count,
                "credits_consumed": credits_consumed,
                "results": results,
                "processing_time_ms": processing_time,
                "batch_id": batch_id,
            }

            return Response(response_data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GSTVerificationHistoryView(generics.ListAPIView):
    """GST verification history endpoint"""

    serializer_class = GSTVerificationResponseSerializer
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Get verification history",
        description="Get GST verification request history for the authenticated user",
        parameters=[
            OpenApiParameter(
                name="gstin",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filter by GSTIN",
            ),
            OpenApiParameter(
                name="status",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filter by status (processing, completed, failed)",
            ),
            OpenApiParameter(
                name="date_from",
                type=OpenApiTypes.DATE,
                location=OpenApiParameter.QUERY,
                description="Filter from date (YYYY-MM-DD)",
            ),
            OpenApiParameter(
                name="date_to",
                type=OpenApiTypes.DATE,
                location=OpenApiParameter.QUERY,
                description="Filter to date (YYYY-MM-DD)",
            ),
        ],
        tags=["GST Services"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        queryset = (
            GSTRequest.objects.filter(user=self.request.user)
            .select_related("api_key", "service")
            .order_by("-created_at")
        )

        # Apply filters
        gstin = self.request.query_params.get("gstin")
        if gstin:
            queryset = queryset.filter(gstin__icontains=gstin)

        status_filter = self.request.query_params.get("status")
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        date_from = self.request.query_params.get("date_from")
        if date_from:
            try:
                date_from = datetime.strptime(date_from, "%Y-%m-%d").date()
                queryset = queryset.filter(created_at__date__gte=date_from)
            except ValueError:
                pass

        date_to = self.request.query_params.get("date_to")
        if date_to:
            try:
                date_to = datetime.strptime(date_to, "%Y-%m-%d").date()
                queryset = queryset.filter(created_at__date__lte=date_to)
            except ValueError:
                pass

        return queryset
