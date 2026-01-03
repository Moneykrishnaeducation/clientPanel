from rest_framework import serializers
from .models import BankDetails, PAMAccount, PAMInvestment
from adminPanel.models import CryptoDetails

class BankDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankDetails
        fields = ['bank_name', 'account_number', 'branch_name', 'ifsc_code', 'bank_doc', 'status', 'created_at', 'updated_at']
        read_only_fields = ['status', 'created_at', 'updated_at']  # These fields are managed by the backend

class CryptoDetailsSerializer(serializers.ModelSerializer):

    user_id = serializers.IntegerField(source='user.id', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)  # for frontend mapping
    exchange = serializers.CharField(source='exchange_name', read_only=True)  # for frontend mapping

    class Meta:
        model = CryptoDetails
        fields = [
            'id', 'user_id', 'user_name', 'user_email', 'email',
            'wallet_address', 'exchange', 'exchange_name', 'currency', 'crypto_doc',
            'status', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user_id', 'user_name', 'user_email', 'email',
            'exchange', 'exchange_name', 'status', 'created_at', 'updated_at'
        ]


class PAMAccountSerializer(serializers.ModelSerializer):
    """Serializer for PAMM Account creation and management"""
    manager_name = serializers.CharField(source='manager.username', read_only=True)
    pool_balance = serializers.DecimalField(max_digits=16, decimal_places=2, read_only=True)
    total_profit = serializers.DecimalField(max_digits=16, decimal_places=2, read_only=True)
    total_investors = serializers.SerializerMethodField()
    mt5_balance = serializers.SerializerMethodField()
    mt5_equity = serializers.SerializerMethodField()
    
    class Meta:
        model = PAMAccount
        fields = [
            'id', 'name', 'strategy', 'min_investment', 'profit_share', 
            'leverage', 'mt5_login', 'enabled', 'created_at', 'updated_at',
            'manager_name', 'pool_balance', 'total_profit', 'total_investors',
            'mt5_balance', 'mt5_equity'
        ]
        read_only_fields = [
            'id', 'mt5_login', 'created_at', 'updated_at', 
            'manager_name', 'pool_balance', 'total_profit', 'total_investors',
            'mt5_balance', 'mt5_equity'
        ]
    
    def get_total_investors(self, obj):
        """Get total number of investors in this PAMM"""
        return obj.investments.count()
    
    def get_mt5_balance(self, obj):
        """Get real-time MT5 balance from TradingAccount"""
        try:
            from adminPanel.models import TradingAccount
            trading_account = TradingAccount.objects.get(account_id=obj.mt5_login)
            return trading_account.balance or 0
        except TradingAccount.DoesNotExist:
            return 0
    
    def get_mt5_equity(self, obj):
        """Get real-time MT5 equity from TradingAccount"""
        try:
            from adminPanel.models import TradingAccount
            trading_account = TradingAccount.objects.get(account_id=obj.mt5_login)
            return trading_account.equity or 0
        except TradingAccount.DoesNotExist:
            return 0
    
    def validate_profit_share(self, value):
        """Validate profit share percentage"""
        if value < 0 or value > 100:
            raise serializers.ValidationError("Profit share must be between 0 and 100 percent")
        return value
    
    def validate_leverage(self, value):
        """Validate leverage value"""
        valid_leverages = [50, 100, 200, 300, 400, 500, 1000]
        if value not in valid_leverages:
            raise serializers.ValidationError(f"Leverage must be one of: {valid_leverages}")
        return value


class PAMAccountCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new PAMM accounts with passwords"""
    master_password = serializers.CharField(write_only=True, min_length=8, max_length=50)
    investor_password = serializers.CharField(write_only=True, min_length=8, max_length=50)
    
    class Meta:
        model = PAMAccount
        fields = [
            'name', 'strategy', 'min_investment', 'profit_share', 
            'leverage', 'master_password', 'investor_password'
        ]
    
    def validate_profit_share(self, value):
        if value < 0 or value > 100:
            raise serializers.ValidationError("Profit share must be between 0 and 100 percent")
        return value
    
    def validate_leverage(self, value):
        valid_leverages = [50, 100, 200, 300, 400, 500, 1000]
        if value not in valid_leverages:
            raise serializers.ValidationError(f"Leverage must be one of: {valid_leverages}")
        return value


class PAMInvestmentSerializer(serializers.ModelSerializer):
    """Serializer for PAMM investments"""
    investor_name = serializers.CharField(source='investor.username', read_only=True)
    investor_email = serializers.CharField(source='investor.email', read_only=True)
    pam_account_name = serializers.CharField(source='pam_account.name', read_only=True)
    manager_name = serializers.CharField(source='pam_account.manager.username', read_only=True)
    pamm_mt5_login = serializers.CharField(source='pam_account.mt5_login', read_only=True)
    allocation_percentage = serializers.DecimalField(max_digits=5, decimal_places=2, read_only=True)
    
    class Meta:
        model = PAMInvestment
        fields = [
            'id', 'amount', 'profit_share', 'mt5_allocation_id', 'created_at',
            'investor_name', 'investor_email', 'pam_account_name', 'manager_name',
            'pamm_mt5_login', 'allocation_percentage', 'pam_account'
        ]
        read_only_fields = [
            'id', 'mt5_allocation_id', 'created_at', 'investor_name', 
            'investor_email', 'pam_account_name', 'manager_name', 'pamm_mt5_login', 'allocation_percentage'
        ]
    
    def validate_amount(self, value):
        """Validate investment amount"""
        if value <= 0:
            raise serializers.ValidationError("Investment amount must be greater than 0")
        return value


class PAMInvestmentCreateSerializer(serializers.Serializer):
    """Serializer for creating new investments. Amount is optional — when omitted
    the system will default to the PAMM's minimum investment.
    """
    pamm_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=16, decimal_places=2, required=False, allow_null=True)

    def validate_amount(self, value):
        # If amount provided, it must be > 0
        if value is None:
            return value
        if value <= 0:
            raise serializers.ValidationError("Investment amount must be greater than 0")
        return value

    def validate_pamm_id(self, value):
        """Validate PAMM account exists and is enabled"""
        try:
            PAMAccount.objects.get(id=value, enabled=True)
            return value
        except PAMAccount.DoesNotExist:
            raise serializers.ValidationError("PAMM account not found or disabled")

    def validate(self, attrs):
        # If amount is missing or null, default to the PAMM's min_investment
        from decimal import Decimal
        if 'amount' not in attrs or attrs.get('amount') is None:
            pamm_id = attrs.get('pamm_id')
            try:
                pam_account = PAMAccount.objects.get(id=pamm_id, enabled=True)
                attrs['amount'] = pam_account.min_investment or Decimal('0.00')
            except PAMAccount.DoesNotExist:
                # Should be caught by validate_pamm_id earlier, but guard anyway
                raise serializers.ValidationError({'pamm_id': 'PAMM account not found or disabled'})
        return attrs


class AvailablePAMAccountSerializer(serializers.ModelSerializer):
    """Serializer for available PAMM accounts (public view)"""
    manager_name = serializers.CharField(source='manager.username', read_only=True)
    pool_balance = serializers.DecimalField(max_digits=16, decimal_places=2, read_only=True)
    total_investors = serializers.SerializerMethodField()
    
    class Meta:
        model = PAMAccount
        fields = [
            'id', 'name', 'strategy', 'min_investment', 'profit_share', 
            'leverage', 'pool_balance', 'total_investors', 'manager_name', 'enabled', 'mt5_login'
        ]
    
    def get_total_investors(self, obj):
        return obj.investments.count()
