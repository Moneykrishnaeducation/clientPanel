from django.db import models
from django.conf import settings

# Use settings.AUTH_USER_MODEL to avoid circular import issues during app loading


class AccountDetails(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    mt5_login = models.CharField(max_length=50, unique=True)  # MT5 account login
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    account_type = models.CharField(max_length=50)
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = 'Account Details'
        
    def __str__(self):
        return f"{self.user.username} - MT5: {self.mt5_login}"

class BankDetails(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    bank_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=50)
    branch_name = models.CharField(max_length=100, null=True, blank=True)  # Made nullable
    ifsc_code = models.CharField(max_length=20, null=True, blank=True)  # Made nullable
    bank_doc = models.FileField(upload_to='bank_docs/', null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = 'Bank Details'

class UserDocument(models.Model):
    DOCUMENT_TYPES = (
        ('identity', 'Identity Document'),
        ('residence', 'Proof of Residence'),
    )
    
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='documents')
    user_email = models.EmailField(max_length=254, db_index=True, help_text="User email for faster document retrieval", default='temp@example.com')
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPES, db_index=True)
    def user_document_path(instance, filename):
        # Use email prefix instead of user ID for better organization
        email_prefix = instance.user_email.split('@')[0] if instance.user_email else str(instance.user.id)
        return f'user_documents/{email_prefix}/{instance.document_type}/{filename}'
        
    document = models.FileField(upload_to=user_document_path)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verified_at = models.DateTimeField(null=True, blank=True, help_text="Timestamp when document was verified")
    mime_type = models.CharField(max_length=100, null=True, blank=True, help_text="MIME type of the uploaded document")
    
    class Meta:
        verbose_name = 'User Document'
        verbose_name_plural = 'User Documents'
        unique_together = ['user', 'document_type']
        indexes = [
            models.Index(fields=['user_email', 'document_type'], name='userdoc_email_type_idx'),
            models.Index(fields=['user_email', 'status'], name='userdoc_email_status_idx'),
            models.Index(fields=['document_type', 'status'], name='userdoc_type_status_idx'),
        ]
        
    def save(self, *args, **kwargs):
        # Auto-populate user_email if not provided
        if not self.user_email and self.user:
            self.user_email = self.user.email
        super().save(*args, **kwargs)
        
    def __str__(self):
        return f"{self.user_email}'s {self.get_document_type_display()}"



class PAMAccount(models.Model):
    """PAMM Account model for manager accounts"""
    id = models.BigAutoField(primary_key=True)
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='pam_accounts'
    )
    name = models.CharField(max_length=200, help_text="Display name for the PAMM account")
    strategy = models.CharField(max_length=200, null=True, blank=True, help_text="Trading strategy description")
    min_investment = models.DecimalField(
        max_digits=14, 
        decimal_places=2, 
        default=0, 
        help_text="Minimum investment amount"
    )
    profit_share = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=0, 
        help_text="Manager profit share in percent"
    )
    leverage = models.IntegerField(default=100, help_text="Leverage for this PAMM account")
    mt5_login = models.CharField(max_length=64, null=True, blank=True, help_text="MT5 account login ID")
    master_password = models.CharField(max_length=128, null=True, blank=True, help_text="Master password for trading")
    investor_password = models.CharField(max_length=128, null=True, blank=True, help_text="Investor password for viewing")
    enabled = models.BooleanField(default=True, help_text="Whether this PAMM account is active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "PAMM Account"
        verbose_name_plural = "PAMM Accounts"

    def __str__(self):
        return f"{self.name} - Manager: {self.manager.username}"

    @property
    def pool_balance(self):
        """Calculate total pool balance from all investments"""
        return self.investments.aggregate(
            total=models.Sum('amount')
        )['total'] or 0

    @property
    def total_profit(self):
        """Calculate total profit distributed"""
        return self.profit_history.aggregate(
            total=models.Sum('profit_amount')
        )['total'] or 0


class PAMInvestment(models.Model):
    """Investment in a PAMM Account"""
    id = models.BigAutoField(primary_key=True)
    investor = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='pam_investments'
    )
    pam_account = models.ForeignKey(
        PAMAccount, 
        on_delete=models.CASCADE, 
        related_name='investments'
    )
    amount = models.DecimalField(max_digits=16, decimal_places=2, help_text="Investment amount")
    profit_share = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=0, 
        help_text="Investor share in percent"
    )
    mt5_allocation_id = models.CharField(
        max_length=128, 
        null=True, 
        blank=True, 
        help_text="MT5 allocation identifier"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "PAMM Investment"
        verbose_name_plural = "PAMM Investments"
        unique_together = ['investor', 'pam_account']  # One investment per user per PAMM

    def __str__(self):
        return f"{self.investor.username} -> {self.pam_account.name} (${self.amount})"

    @property
    def allocation_percentage(self):
        """Calculate allocation percentage in the pool"""
        total_pool = self.pam_account.pool_balance
        if total_pool > 0:
            return float(self.amount / total_pool * 100)
        return 0.0


class PAMProfitHistory(models.Model):
    """Historical profit distribution records"""
    id = models.BigAutoField(primary_key=True)
    pam_account = models.ForeignKey(
        PAMAccount, 
        on_delete=models.CASCADE, 
        related_name='profit_history'
    )
    investor = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='pam_profit_history'
    )
    profit_amount = models.DecimalField(max_digits=16, decimal_places=2, help_text="Profit amount distributed")
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "PAMM Profit History"
        verbose_name_plural = "PAMM Profit History"

    def __str__(self):
        return f"${self.profit_amount} to {self.investor.username} from {self.pam_account.name}"
