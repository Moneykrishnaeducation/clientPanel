"""
MT5 service for handling account synchronization and lookups
"""
from django.conf import settings
from adminPanel.mt5.models import ServerSetting
from adminPanel.mt5.manager import MT5ManagerAPI
import logging

logger = logging.getLogger(__name__)

class MT5Service:
    def __init__(self):
        self.manager = None
        
    def get_connection(self):
        """Get or create MT5 connection"""
        try:
            if not self.manager:
                self.manager = MT5ManagerAPI()
            return self.manager
        except Exception as e:
            logger.error(f"Failed to get MT5 connection: {e}")
            return None

    def get_account_info(self, login_id):
        """Get account information from MT5"""
        try:
            manager = self.get_connection()
            if not manager:
                return None
                
            try:
                # Get live data from MT5
                account = manager.manager.UserAccountGet(int(login_id))
                if not account:
                    logger.warning(f"Account {login_id} not found in MT5")
                    return None
                    
                # Return comprehensive account info
                return {
                    'login': str(login_id),
                    'balance': float(account.Balance),
                    'equity': float(account.Equity),
                    'margin': float(getattr(account, 'Margin', 0.00)),
                    'margin_free': float(getattr(account, 'MarginFree', 0.00)),
                    'margin_level': float(getattr(account, 'MarginLevel', 0.00)),
                    'currency': 'USD'
                }
                
            except Exception as mt5_error:
                logger.error(f"MT5 lookup failed for account {login_id}: {mt5_error}")
                return None
                
        except Exception as e:
            logger.error(f"Unexpected error in MT5 get_account_info: {e}", exc_info=True)
            return None
            
    def sync_account(self, login_id):
        """Sync account details with MT5"""
        try:
            info = self.get_account_info(login_id)
            if not info:
                return False
                
            # Update local account details
            from adminPanel.models import TradingAccount
            try:
                account = TradingAccount.objects.get(account_id=login_id)
                account.balance = info['balance']
                account.save()
                
                return True
            except TradingAccount.DoesNotExist:
                logger.warning(f"Account {login_id} not found in database")
                return False
                
        except Exception as e:
            logger.error(f"Error syncing MT5 account: {e}")
            return False

    def create_pamm_account(self, name, email, phone, profit_share, leverage, master_password, investor_password):
        """Create a PAMM (manager) account on MT5 and return standardized result."""
        try:
            # Prefer using the central MT5 service actions where available
            try:
                from adminPanel.mt5.services import MT5ManagerActions
                mt5_actions = MT5ManagerActions()
            except Exception:
                mt5_actions = None

            # If MT5ManagerActions provides a create_account method, use it
            if mt5_actions and hasattr(mt5_actions, 'create_account'):
                result = mt5_actions.create_account(
                    name=name,
                    email=email,
                    phone=phone,
                    leverage=leverage,
                    password=master_password,
                    investor_password=investor_password,
                    account_type='real'
                )
                if not result:
                    return {'success': False, 'error': 'MT5 account creation failed'}
                # result expected to be dict with 'login' or similar
                login = result.get('login') or result.get('mt5_login') or getattr(result, 'Login', None)
                return {
                    'success': True,
                    'mt5_login': login,
                    'master_password': master_password,
                    'investor_password': investor_password,
                    'raw': result
                }

            # Fallback: try using adminPanel.mt5.services.MT5ManagerActions.add_new_account
            if mt5_actions and hasattr(mt5_actions, 'add_new_account'):
                # create a temporary user-like object for add_new_account expecting 'client' param
                class _TmpClient:
                    def __init__(self, name, email, phone):
                        self.first_name = name
                        self.last_name = ''
                        self.email = email
                        self.country = ''
                        self.phone_number = phone

                tmp_client = _TmpClient(name, email, phone)
                login = mt5_actions.add_new_account(group_name=None, leverage=leverage, client=tmp_client,
                                                    master_password=master_password, investor_password=investor_password)
                if not login:
                    return {'success': False, 'error': 'MT5 add_new_account failed'}
                return {
                    'success': True,
                    'mt5_login': login,
                    'master_password': master_password,
                    'investor_password': investor_password
                }

            # Last resort: indicate failure
            return {'success': False, 'error': 'No MT5 action available to create account'}

        except Exception as e:
            logger.error(f"Error in create_pamm_account wrapper: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

# Global instance
mt5_service = MT5Service()
