"""
PAMM service layer for business logic
"""
from django.db import transaction
from django.contrib.auth import get_user_model
from ..models import PAMAccount, PAMInvestment
from ..services.mt5_service import mt5_service
from adminPanel.EmailSender import EmailSender
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class PAMMService:
    """Service layer for PAMM operations"""
    
    @staticmethod
    @transaction.atomic
    def create_pamm_account(user, data):
        """
        Create a new PAMM account with MT5 integration
        
        Args:
            user: User instance (manager)
            data: Dictionary containing PAMM account data
            
        Returns:
            tuple: (success: bool, result: dict/PAMAccount, error: str)
        """
        try:
            # Extract data
            name = data.get('name')
            strategy = data.get('strategy', '')
            min_investment = data.get('min_investment', 0)
            profit_share = data.get('profit_share')
            leverage = data.get('leverage')
            master_password = data.get('master_password')
            investor_password = data.get('investor_password')
            
            # Validate required fields
            if not all([name, profit_share, leverage, master_password, investor_password]):
                return False, None, "Missing required fields"
            
            # Create MT5 account
            # logger.info(f"Creating MT5 account for PAMM: {name}")
            mt5_result = mt5_service.create_pamm_account(
                name=name,
                email=user.email,
                phone=getattr(user, 'phone', ''),
                profit_share=profit_share,
                leverage=leverage,
                master_password=master_password,
                investor_password=investor_password
            )
            
            if not mt5_result.get('success'):
                logger.error(f"MT5 account creation failed: {mt5_result.get('error')}")
                return False, None, f"MT5 account creation failed: {mt5_result.get('error')}"
            
            # Create PAMM account in database
            pamm_account = PAMAccount.objects.create(
                manager=user,
                name=name,
                strategy=strategy,
                min_investment=min_investment,
                profit_share=profit_share,
                leverage=leverage,
                mt5_login=mt5_result['mt5_login'],
                master_password=mt5_result['master_password'],
                investor_password=mt5_result['investor_password'],
                enabled=True
            )
            
            logger.info(f"PAMM account created successfully: {pamm_account.id}")
            
            # Send email notification
            try:
                PAMMService._send_pamm_creation_email(user, pamm_account, mt5_result)
            except Exception as email_error:
                logger.error(f"Failed to send PAMM creation email: {email_error}")
                # Don't fail the whole operation for email issues
            
            return True, pamm_account, None
            
        except Exception as e:
            logger.error(f"Error creating PAMM account: {e}")
            return False, None, str(e)
    
    @staticmethod
    @transaction.atomic
    def invest_in_pamm(user, pamm_id, amount):
        """
        Create an investment in a PAMM account
        
        Args:
            user: User instance (investor)
            pamm_id: PAMM account ID
            amount: Investment amount
            
        Returns:
            tuple: (success: bool, result: PAMInvestment, error: str)
        """
        try:
            # Get PAMM account
            try:
                pamm_account = PAMAccount.objects.get(id=pamm_id, enabled=True)
            except PAMAccount.DoesNotExist:
                return False, None, "PAMM account not found or disabled"
            
            # Check minimum investment
            if amount < pamm_account.min_investment:
                return False, None, f"Minimum investment is ${pamm_account.min_investment}"
            
            # Check if user already invested (update existing or create new based on business logic)
            existing_investment = PAMInvestment.objects.filter(
                investor=user, 
                pam_account=pamm_account
            ).first()
            
            if existing_investment:
                # Update existing investment
                existing_investment.amount += amount
                existing_investment.save()
                investment = existing_investment
                # logger.info(f"Updated existing investment: {investment.id}")
            else:
                # Create new investment
                investment = PAMInvestment.objects.create(
                    investor=user,
                    pam_account=pamm_account,
                    amount=amount,
                    profit_share=100 - pamm_account.profit_share  # Investor gets remaining percentage
                )
                logger.info(f"Created new investment: {investment.id}")
            
            # Send investor credentials email
            try:
                PAMMService._send_investment_credentials_email(user, pamm_account, investment)
            except Exception as email_error:
                logger.error(f"Failed to send investment credentials email: {email_error}")
                # Don't fail the operation for email issues
            
            return True, investment, None
            
        except Exception as e:
            logger.error(f"Error creating PAMM investment: {e}")
            return False, None, str(e)
    
    @staticmethod
    def get_available_pamm_accounts(exclude_user=None):
        """Get all available PAMM accounts for investment (optionally exclude user's own accounts)"""
        queryset = PAMAccount.objects.filter(enabled=True).select_related('manager')
        if exclude_user:
            # Exclude PAMMs managed by the user
            queryset = queryset.exclude(manager=exclude_user)
            # Also exclude PAMMs where the user already has an investment
            # (unique_together on investor+pam_account ensures one row per user/pamm)
            queryset = queryset.exclude(investments__investor=exclude_user)
        return queryset.distinct()
    
    @staticmethod
    def get_user_managed_pamm_accounts(user):
        """Get PAMM accounts managed by user"""
        return PAMAccount.objects.filter(manager=user).prefetch_related('investments')
    
    @staticmethod
    def get_user_investments(user):
        """Get user's PAMM investments"""
        return PAMInvestment.objects.filter(investor=user).select_related('pam_account', 'pam_account__manager')
    
    @staticmethod
    def _send_pamm_creation_email(user, pamm_account, mt5_result):
        """Send PAMM account creation email"""
        try:
            # Send email synchronously to avoid relying on Celery/Redis broker
            EmailSender.send_pamm_account_created_email(
                user_email=user.email,
                user_name=user.get_full_name() or user.username,
                pamm_name=pamm_account.name,
                account_id=pamm_account.mt5_login,
                master_password=mt5_result['master_password'],
                investor_password=mt5_result['investor_password'],
                leverage=pamm_account.leverage,
                profit_share=pamm_account.profit_share,
                login_url="https://client.vtindex.com",
                company_name="VTIndex"
            )
            # logger.info(f"PAMM creation email sent synchronously to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send PAMM creation email: {e}")
            raise
    
    @staticmethod
    def _send_investment_credentials_email(user, pamm_account, investment):
        """Send investment credentials email"""
        try:
            # Send email synchronously to avoid relying on Celery/Redis broker
            EmailSender.send_pamm_investment_credentials_email(
                user_email=user.email,
                user_name=user.get_full_name() or user.username,
                pamm_name=pamm_account.name,
                manager_name=pamm_account.manager.get_full_name() or pamm_account.manager.username,
                investment_amount=investment.amount,
                account_id=pamm_account.mt5_login,
                investor_password=pamm_account.investor_password,
                login_url="https://client.vtindex.com",
                company_name="VTIndex"
            )
            # logger.info(f"Investment credentials email sent synchronously to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send investment credentials email: {e}")
            raise
