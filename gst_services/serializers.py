from rest_framework import serializers

from django.core.validators import RegexValidator

from .models import GSTRequest, GSTService, GSTVerificationResult


class GSTServiceSerializer(serializers.ModelSerializer):
    """Serializer for GST Service model"""

    class Meta:
        model = GSTService
        fields = [
            "id",
            "name",
            "slug",
            "description",
            "endpoint_path",
            "credit_cost",
            "rate_limit_per_minute",
            "rate_limit_per_hour",
            "rate_limit_per_day",
            "is_active",
            "is_premium",
            "documentation_url",
            "example_request",
            "example_response",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class GSTINValidationSerializer(serializers.Serializer):
    """Serializer for GSTIN validation request"""

    gstin = serializers.CharField(
        max_length=15,
        min_length=15,
        validators=[
            RegexValidator(
                regex=r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$",
                message="Invalid GSTIN format. GSTIN must be 15 characters long and follow the pattern: 22AAAAA0000A1Z5",
            )
        ],
        help_text="15-digit GSTIN number (e.g., 22AAAAA0000A1Z5)",
    )

    def validate_gstin(self, value):
        """Additional GSTIN validation"""
        # Convert to uppercase
        value = value.upper()

        # Check state code (first 2 digits)
        state_code = value[:2]
        valid_state_codes = [
            "01",
            "02",
            "03",
            "04",
            "05",
            "06",
            "07",
            "08",
            "09",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
            "16",
            "17",
            "18",
            "19",
            "20",
            "21",
            "22",
            "23",
            "24",
            "25",
            "26",
            "27",
            "28",
            "29",
            "30",
            "31",
            "32",
            "33",
            "34",
            "35",
            "36",
            "37",
            "38",
            "96",
            "97",
            "99",
        ]

        if state_code not in valid_state_codes:
            raise serializers.ValidationError("Invalid state code in GSTIN")

        return value


class GSTVerificationRequestSerializer(serializers.ModelSerializer):
    """Serializer for GST Verification Request model"""

    class Meta:
        model = GSTRequest
        fields = [
            "id",
            "request_id",
            "user",
            "api_key",
            "service",
            "method",
            "endpoint",
            "request_headers",
            "request_body",
            "request_params",
            "response_status_code",
            "response_headers",
            "response_body",
            "response_time_ms",
            "credits_consumed",
            "billing_status",
            "ip_address",
            "user_agent",
            "status",
            "error_message",
            "error_code",
            "created_at",
        ]
        read_only_fields = ["id", "request_id", "user", "api_key", "created_at"]


class GSTVerificationResponseSerializer(serializers.ModelSerializer):
    """Serializer for GST Verification Response model"""

    class Meta:
        model = GSTVerificationResult
        fields = [
            "id",
            "request",
            "gstin",
            "legal_name",
            "trade_name",
            "business_type",
            "constitution",
            "address",
            "state_code",
            "state_name",
            "pincode",
            "registration_date",
            "cancellation_date",
            "status",
            "is_verified",
            "verification_confidence",
            "additional_data",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class GSTVerificationSerializer(serializers.Serializer):
    """Serializer for GST verification API request"""

    gstin = serializers.CharField(
        max_length=15,
        min_length=15,
        validators=[
            RegexValidator(
                regex=r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$",
                message="Invalid GSTIN format",
            )
        ],
    )

    include_details = serializers.BooleanField(
        default=True, help_text="Include detailed business information in response"
    )

    def validate_gstin(self, value):
        """Validate GSTIN format and checksum"""
        value = value.upper()

        # Validate checksum digit
        if not self._validate_gstin_checksum(value):
            raise serializers.ValidationError("Invalid GSTIN checksum")

        return value

    def _validate_gstin_checksum(self, gstin):
        """Validate GSTIN checksum using the official algorithm"""
        try:
            # GSTIN checksum validation algorithm
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


class GSTDetailsSerializer(serializers.Serializer):
    """Serializer for GST details response"""

    gstin = serializers.CharField()
    legal_name = serializers.CharField()
    trade_name = serializers.CharField(allow_blank=True)
    registration_date = serializers.DateField()
    constitution_of_business = serializers.CharField()
    taxpayer_type = serializers.CharField()
    status = serializers.CharField()

    # Address information
    principal_place_address = serializers.DictField()
    additional_places_of_business = serializers.ListField(
        child=serializers.DictField(), required=False
    )

    # Business activities
    nature_of_business_activities = serializers.ListField(
        child=serializers.CharField(), required=False
    )

    # Compliance information
    filing_status = serializers.ListField(child=serializers.DictField(), required=False)

    # Verification metadata
    verification_date = serializers.DateTimeField()
    data_source = serializers.CharField()
    is_active = serializers.BooleanField()


class GSTComplianceSerializer(serializers.Serializer):
    """Serializer for GST compliance check request"""

    gstin = serializers.CharField(
        max_length=15,
        min_length=15,
        validators=[
            RegexValidator(
                regex=r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$",
                message="Invalid GSTIN format",
            )
        ],
    )

    check_period = serializers.CharField(
        max_length=7,
        help_text="Period in MM-YYYY format (e.g., 03-2024)",
        validators=[
            RegexValidator(
                regex=r"^(0[1-9]|1[0-2])-20[0-9]{2}$",
                message="Invalid period format. Use MM-YYYY format",
            )
        ],
    )


class GSTComplianceResponseSerializer(serializers.Serializer):
    """Serializer for GST compliance response"""

    gstin = serializers.CharField()
    period = serializers.CharField()
    filing_status = serializers.CharField()
    return_type = serializers.CharField()
    due_date = serializers.DateField(allow_null=True)
    filed_date = serializers.DateField(allow_null=True)
    is_compliant = serializers.BooleanField()
    penalty_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, allow_null=True
    )


class GSTSearchSerializer(serializers.Serializer):
    """Serializer for GST search request"""

    query = serializers.CharField(
        max_length=200, help_text="Search query (business name, GSTIN, or PAN)"
    )

    search_type = serializers.ChoiceField(
        choices=[
            ("name", "Business Name"),
            ("gstin", "GSTIN"),
            ("pan", "PAN"),
            ("all", "All Fields"),
        ],
        default="all",
    )

    state_code = serializers.CharField(
        max_length=2, required=False, help_text="Filter by state code (01-37)"
    )

    limit = serializers.IntegerField(
        min_value=1,
        max_value=100,
        default=10,
        help_text="Maximum number of results to return",
    )


class GSTSearchResultSerializer(serializers.Serializer):
    """Serializer for GST search results"""

    gstin = serializers.CharField()
    legal_name = serializers.CharField()
    trade_name = serializers.CharField(allow_blank=True)
    status = serializers.CharField()
    registration_date = serializers.DateField()
    state_name = serializers.CharField()
    business_type = serializers.CharField()
    match_score = serializers.FloatField()


class BulkGSTVerificationSerializer(serializers.Serializer):
    """Serializer for bulk GST verification request"""

    gstins = serializers.ListField(
        child=serializers.CharField(
            max_length=15,
            min_length=15,
            validators=[
                RegexValidator(
                    regex=r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$",
                    message="Invalid GSTIN format",
                )
            ],
        ),
        min_length=1,
        max_length=100,
        help_text="List of GSTINs to verify (max 100)",
    )

    include_details = serializers.BooleanField(
        default=False, help_text="Include detailed information for each GSTIN"
    )

    def validate_gstins(self, value):
        """Validate list of GSTINs"""
        # Remove duplicates while preserving order
        seen = set()
        unique_gstins = []
        for gstin in value:
            gstin_upper = gstin.upper()
            if gstin_upper not in seen:
                seen.add(gstin_upper)
                unique_gstins.append(gstin_upper)

        return unique_gstins


class BulkGSTVerificationResponseSerializer(serializers.Serializer):
    """Serializer for bulk GST verification response"""

    total_requested = serializers.IntegerField()
    total_processed = serializers.IntegerField()
    total_valid = serializers.IntegerField()
    total_invalid = serializers.IntegerField()
    credits_consumed = serializers.IntegerField()

    results = serializers.ListField(child=serializers.DictField())

    processing_time_ms = serializers.IntegerField()
    batch_id = serializers.CharField()
