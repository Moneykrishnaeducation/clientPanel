from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.authentication import JWTAuthentication

from adminPanel.authentication import BlacklistCheckingJWTAuthentication
import logging
import time
from adminPanel.mt5.services import MT5ManagerActions, crights, reset_manager_instance
from adminPanel.models import TradingAccount, Transaction
from adminPanel.serializers import TransactionSerializer
from django.core.cache import cache
from django.db import models

logger = logging.getLogger(__name__)

# Do NOT create a global MT5ManagerActions instance at import time.
# Creating it on import can cause the manager to be created before Django
# finishes startup or before ServerSetting is available which leads to
# intermittent "manager not connected" errors returned as HTTP 503.


def get_mt5_service(retry_on_fail=True, retry_delay=1.0):
    """Return a MT5ManagerActions instance that is connected if possible.

    If the manager is not connected, optionally attempt a single reset+retry
    to reinitialize the manager using `reset_manager_instance()`.
    """
    service = MT5ManagerActions()
    if getattr(service, 'manager', None):
        return service

    # No manager available. Optionally attempt a reset and retry once.
    if retry_on_fail:
        logger.warning("MT5 manager not connected, attempting reset and retry")
        try:
            reset_manager_instance()
        except Exception as e:
            logger.error(f"Failed to reset MT5 manager instance: {e}")
            return service

        # Wait briefly for reconnection to happen (manager init occurs on demand)
        time.sleep(retry_delay)
        service = MT5ManagerActions()
        return service

    return service


@method_decorator(csrf_exempt, name='dispatch')
class AccountDetailsView(APIView):
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, account_id):
        try:
           
            # Get and verify account access
            account = None
            try:
                # First try direct ownership
                account = get_object_or_404(TradingAccount, account_id=account_id, user=request.user)
    
            except (TradingAccount.DoesNotExist, Http404):
                # Not owned by requesting user. Try to allow access for staff or IB parent relationship
                try:
                    possible_account = TradingAccount.objects.get(account_id=account_id)
                    # Allow if requesting user is staff
                    if getattr(request.user, 'is_staff', False):
                        account = possible_account
                        logger.debug(f"Staff user {request.user.id} accessing account {account.account_id}")
                    else:
                        # Allow if requesting user is parent IB of the account owner
                        account_owner = getattr(possible_account, 'user', None)
                        parent_ib = getattr(account_owner, 'parent_ib', None) if account_owner is not None else None
                        if parent_ib is not None and getattr(parent_ib, 'id', None) == getattr(request.user, 'id', None):
                            account = possible_account
                            logger.debug(f"IB parent {request.user.id} accessing child account {account.account_id}")
                        else:
                            # If still not allowed, check MAM investment relationship
                            try:
                                investment_account = TradingAccount.objects.get(
                                    user=request.user,
                                    account_type='mam_investment',
                                    mam_master_account__account_id=account_id
                                )
                                # If user has an investment account with this manager, allow access to manager's details
                                account = investment_account.mam_master_account
                                logger.debug(f"Found MAM manager account through investment: {account.account_id}")
                            except TradingAccount.DoesNotExist:
                                logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                                return Response({
                                    'error': 'Account not found or you do not have permission to access it'
                                }, status=status.HTTP_404_NOT_FOUND)
                except TradingAccount.DoesNotExist:
                    logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                    return Response({
                        'error': 'Account not found or you do not have permission to access it'
                    }, status=status.HTTP_404_NOT_FOUND)
            
            # Get account info from MT5 (lazy service creation)
            try:
                _mt5 = get_mt5_service()
                if not getattr(_mt5, 'manager', None):
                    raise Exception('MT5 Manager is not connected')
                account_info = _mt5.get_account_info(account_id)
            except Exception as mt5_error:
                logger.warning(f"MT5 lookup failed: {mt5_error}")
                account_info = None
            
            if not account_info:
                # Return account data from database if MT5 lookup fails
                logger.info("Using database fallback data")
                return Response({
                    'account_id': account.account_id,
                    'balance': float(account.balance or 0.00),
                    'leverage': account.leverage,
                    'type': account.account_type,
                    'status': account.status,
                    'algo_enabled': account.algo_enabled if hasattr(account, 'algo_enabled') else False,
                    'currency': 'USD'
                }, content_type='application/json')
            
            # Return combined data from MT5 and database
            response_data = {
                'account_id': account.account_id,
                'balance': float(account_info.get('balance', 0.00)),
                'equity': float(account_info.get('equity', 0.00)),
                'leverage': account.leverage,
                'type': account.account_type,
                'status': account.status,
                'algo_enabled': account.algo_enabled if hasattr(account, 'algo_enabled') else False,
                'currency': account_info.get('currency', 'USD')
            }
            return Response(response_data, content_type='application/json')

        except TradingAccount.DoesNotExist:
            logger.warning(f"Account {account_id} not found or not owned by user {request.user.id}")
            return Response({
                'error': 'Account not found or you do not have permission to access it'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error in account details view: {e}", exc_info=True)
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class OpenPositionsView(APIView):
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, account_id):
        try:
            logger.info(f"Fetching open positions for account_id: {account_id}, user: {request.user.id}")
            
            # Get and verify account access
            account = None
            try:
                # First try direct ownership
                account = get_object_or_404(TradingAccount, account_id=account_id, user=request.user)
   
            except (TradingAccount.DoesNotExist, Http404):
                # Not owned by requesting user. Try to allow access for staff or IB parent relationship
                try:
                    possible_account = TradingAccount.objects.get(account_id=account_id)
                    # Allow if requesting user is staff
                    if getattr(request.user, 'is_staff', False):
                        account = possible_account
                        logger.debug(f"Staff user {request.user.id} accessing account {account.account_id}")
                    else:
                        # Allow if requesting user is parent IB of the account owner
                        account_owner = getattr(possible_account, 'user', None)
                        parent_ib = getattr(account_owner, 'parent_ib', None) if account_owner is not None else None
                        if parent_ib is not None and getattr(parent_ib, 'id', None) == getattr(request.user, 'id', None):
                            account = possible_account
                            logger.debug(f"IB parent {request.user.id} accessing child account {account.account_id}")
                        else:
                            # If still not allowed, check MAM investment relationship
                            try:
                                investment_account = TradingAccount.objects.get(
                                    user=request.user,
                                    account_type='mam_investment',
                                    mam_master_account__account_id=account_id
                                )
                                # If user has an investment account with this manager, allow access to manager's positions
                                account = investment_account.mam_master_account
                                logger.debug(f"Found MAM manager account through investment: {account.account_id}")
                            except TradingAccount.DoesNotExist:
                                logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                                return Response({
                                    'success': False,
                                    'message': 'Trading account not found or access denied'
                                }, status=status.HTTP_404_NOT_FOUND)
                except TradingAccount.DoesNotExist:
                    logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                    return Response({
                        'success': False,
                        'message': 'Trading account not found or access denied'
                    }, status=status.HTTP_404_NOT_FOUND)
            
            # Get open positions from MT5 (lazy service creation)
            try:
                _mt5 = get_mt5_service()
                if not getattr(_mt5, 'manager', None):
                    raise Exception('MT5 Manager is not connected')
                mt5_positions = _mt5.get_open_positions(int(account_id))
                
                # Transform MT5 data to match frontend expectations
                formatted_positions = []
                for pos in mt5_positions:
                    formatted_pos = {
                        'ticket': str(pos.get('id', '')),
                        'symbol': pos.get('symbol', ''),
                        'type': pos.get('type', ''),  # MT5 returns 'Buy' or 'Sell'
                        'volume': float(pos.get('volume', 0)),
                        'open_price': float(pos.get('price', 0)),
                        'current_price': float(pos.get('current_price', pos.get('price', 0))),
                        'sl': float(pos.get('sl', 0)),
                        'tp': float(pos.get('tp', 0)),
                        'profit': float(pos.get('profit', 0)),
                        'swap': float(pos.get('swap', 0)),
                        'open_time': str(pos.get('date', '')),
                        'comment': pos.get('comment', '')
                    }
                    formatted_positions.append(formatted_pos)
                
                mt5_status = 'online'
            except Exception as mt5_error:
                logger.error(f"MT5 lookup failed for account {account_id}: {mt5_error}")
                
                # Generate user-friendly error message
                error_msg = str(mt5_error)
                if "Manager instance is None" in error_msg or "not connected" in error_msg.lower():
                    user_message = "MT5 Manager is not connected. Please reconnect."
                elif "Failed to connect" in error_msg:
                    user_message = "Unable to connect to MT5 server. Please try again later."
                elif "permission" in error_msg.lower() or "unauthorized" in error_msg.lower():
                    user_message = "MT5 server permissions insufficient. Please contact support."
                else:
                    user_message = "MT5 server is currently unavailable. Please try again later."
                
                # Return error response when MT5 is unavailable - no sample data
                return Response({
                    'success': False,
                    'message': user_message,
                    'technical_details': str(mt5_error),  # Include technical details for debugging
                    'data': {
                        'positions': [],
                        'mt5_status': 'offline'
                    },
                    'positions': [],  # Empty array for backward compatibility
                    'mt5_status': 'offline'
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            
            return Response({
                'success': True,
                'data': {
                    'positions': formatted_positions,
                    'mt5_status': mt5_status
                },
                'positions': formatted_positions,  # Also include at top level for backward compatibility
                'mt5_status': mt5_status
            })
            
        except Exception as e:
            logger.error(f"Error fetching positions for account {account_id}: {str(e)}")
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class BankDetailsView(LoginRequiredMixin, View):
    def get(self, request):
        try:
            # TODO: Implement actual bank details retrieval
            return JsonResponse({
                'success': True,
                'data': {
                    'bank_name': 'Sample Bank',
                    'account_number': 'XXXXXXXXXXXX',
                    'swift_code': 'SAMPLEXX',
                    'iban': 'XX00 0000 0000 0000'
                }
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class CryptoDetailsView(LoginRequiredMixin, View):
    def get(self, request):
        try:
            # TODO: Implement actual crypto details retrieval
            return JsonResponse({
                'success': True,
                'data': {
                    'wallet_address': '0x0000000000000000000000000000000000000000',
                    'network': 'ETH',
                    'currency': 'USDT'
                }
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class ToggleAlgoTradingView(APIView):
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, account_id):
        import traceback
        try:
            logger.info(f"Toggling algo trading for account {account_id}")
            # Get MT5 service lazily and verify connection
            _mt5 = get_mt5_service()
            if not getattr(_mt5, 'manager', None):
                logger.error("MT5 Manager connection is not available")
                return Response({
                    'error': 'MT5 service is not available',
                    'details': 'Could not connect to MT5 Manager API'
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

            # Get and verify account ownership
            account = get_object_or_404(TradingAccount, account_id=account_id, user=request.user)

            # Verify account exists in MT5
            try:
                mt5_account = _mt5.get_account_info(account_id)
                if not mt5_account:
                    logger.error(f"Account {account_id} not found in MT5")
                    return Response({
                        'error': 'Account not found in MT5',
                        'details': f'Account {account_id} exists in database but not in MT5'
                    }, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                logger.error(f"Error checking MT5 account {account_id}: {str(e)}")
                logger.error(traceback.format_exc())
                return Response({
                    'error': 'Failed to verify account in MT5',
                    'details': str(e),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Get enabled status from request
            enabled = request.data.get('enabled', False)
            logger.info(f"Setting algo trading to: {enabled}")

            # Get current MT5 algo status before update
            try:
                current_rights = getattr(mt5_account, 'Rights', 0)
                current_status = bool(current_rights & crights.USER_RIGHT_EXPERT)
                logger.info(f"Current algo trading status: {current_status}")
                logger.info(f"Current rights: {current_rights} (binary: {bin(current_rights)}, EXPERT bit: {current_status})")
                logger.info("Proceeding with rights update to ensure correct state")
            except Exception as e:
                logger.warning(f"Could not check current algo status: {str(e)}")
                logger.warning(traceback.format_exc())

            # Try to update in MT5
            try:
                mt5_result = _mt5.toggle_algo(account_id, 'enable' if enabled else 'disable')
                if not mt5_result:
                    logger.error(f"MT5 algo trading toggle failed for account {account_id}")
                    return Response({
                        'error': 'Failed to update algo trading status in MT5',
                        'details': 'MT5 service reported failure but did not provide error details'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                logger.info(f"Successfully updated MT5 algo trading status to {enabled}")
            except Exception as mt5_error:
                logger.error(f"MT5 error while toggling algo trading: {str(mt5_error)}")
                logger.error(traceback.format_exc())
                return Response({
                    'error': 'MT5 operation failed',
                    'details': str(mt5_error),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Update database after successful MT5 update
            account.algo_enabled = enabled
            account.save()

            # Verify the change in MT5
            try:
                updated_account = _mt5.get_account_info(account_id)
                actual_rights = getattr(updated_account, 'Rights', 0)
                actual_status = bool(actual_rights & crights.USER_RIGHT_EXPERT)

                if actual_status != enabled:
                    logger.warning(f"MT5 algo status mismatch - expected: {enabled}, actual: {actual_status}, rights: {actual_rights}")
                    # Revert database change if MT5 status doesn't match
                    account.algo_enabled = actual_status
                    account.save()
                    return Response({
                        'error': 'MT5 status verification failed',
                        'details': f'Expected status: {enabled}, actual status: {actual_status}',
                        'data': {
                            'account_id': account_id,
                            'algo_trading_enabled': actual_status
                        }
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Exception as e:
                logger.warning(f"Could not verify final MT5 algo status: {str(e)}")
                logger.warning(traceback.format_exc())
                actual_status = enabled  # Fall back to requested status

            return Response({
                'success': True,
                'message': f'Algo trading {"enabled" if enabled else "disabled"} successfully',
                'data': {
                    'account_id': account_id,
                    'algo_trading_enabled': actual_status
                }
            }, content_type='application/json')

        except TradingAccount.DoesNotExist:
            logger.warning(f"Account {account_id} not found or not owned by user {request.user.id}")
            return Response({
                'error': 'Trading account not found',
                'details': 'Account does not exist or you do not have permission to access it'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error toggling algo trading: {str(e)}")
            logger.error(traceback.format_exc())
            return Response({
                'error': 'Internal server error',
                'details': str(e),
                'traceback': traceback.format_exc()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class UserTradingAccountsView(APIView):
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            # Log authentication attempt for debugging
            # logger.info(f"UserTradingAccountsView: User authenticated: {request.user.is_authenticated}, User: {request.user}")
            # logger.debug(f"Cookies received: {list(request.COOKIES.keys())}")
            
            if not request.user.is_authenticated:
                logger.warning("UserTradingAccountsView: User not authenticated")
                return Response({
                    'success': False,
                    'message': 'Authentication required',
                    'error': 'User is not authenticated'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Return cached payload for this user if available to avoid duplicate work
            cache_key = f"user_trading_accounts_{request.user.id}"
            cached_payload = cache.get(cache_key)
            if cached_payload is not None:
                logger.debug(f"Returning cached accounts for user {request.user.id}")
                return Response(cached_payload, status=status.HTTP_200_OK)
            
            mt5_service = MT5ManagerActions()
            
            # Check MT5 connection
            if not mt5_service.manager:
                logger.error("MT5 Manager connection failed")
                return Response({
                    'success': False,
                    'message': 'MT5 connection is not available',
                    'accounts': [],
                    'mt5_status': 'disconnected'
                }, status=status.HTTP_200_OK)
            
            # Get accounts from database
            db_accounts = TradingAccount.objects.filter(user=request.user)
            db_accounts_dict = {str(acc.account_id): acc for acc in db_accounts}
            
            # Get all MT5 accounts
            mt5_accounts = mt5_service.list_mt5_accounts() or []
            mt5_accounts_dict = {str(acc['login']): acc for acc in mt5_accounts}
            
            # Process accounts and sync with MT5
            accounts_data = []
            sync_errors = []
            
            # Process DB accounts and sync with MT5
            for account_id, db_account in db_accounts_dict.items():
                try:
                    # Try to get account info from MT5
                    mt5_info = mt5_accounts_dict.get(account_id)
                    
                    if not mt5_info:
                        # Double check directly with MT5
                        mt5_info = mt5_service.get_account_info(account_id)
                    
                    if not mt5_info:
                        # Account doesn't exist in MT5, mark as inactive
                        logger.warning(f"Account {account_id} not found in MT5, marking as inactive")
                        db_account.is_active = False
                        db_account.save()
                        continue
                    
                    # Resolve group information
                    group_alias = ''
                    group_identifier = ''
                    try:
                        from adminPanel.models import TradeGroup

                        # Helper to robustly resolve a TradeGroup from various MT5/group strings
                        def resolve_tradegroup_by_string(s):
                            if not s:
                                return None
                            # Try exact matches first (case-insensitive)
                            tg = TradeGroup.objects.filter(models.Q(name__iexact=s) | models.Q(group_id__iexact=s)).first()
                            if tg:
                                return tg
                            # Try unescaping double backslashes
                            try:
                                s_unescaped = s.replace('\\\\', '\\')
                                if s_unescaped != s:
                                    tg = TradeGroup.objects.filter(models.Q(name__iexact=s_unescaped) | models.Q(group_id__iexact=s_unescaped)).first()
                                    if tg:
                                        return tg
                            except Exception:
                                pass
                            # Try icontains match
                            tg = TradeGroup.objects.filter(models.Q(name__icontains=s) | models.Q(group_id__icontains=s)).first()
                            if tg:
                                return tg
                            # Try last segment after backslash or slash
                            try:
                                last = s.split('\\')[-1].split('/')[-1]
                                if last and last != s:
                                    tg = TradeGroup.objects.filter(models.Q(name__iexact=last) | models.Q(group_id__iexact=last)).first()
                                    if tg:
                                        return tg
                            except Exception:
                                pass
                            return None

                        # Helper to extract clean alias from MT5 group name or TradeGroup
                        def get_clean_alias(tg, fallback_name=''):
                            if tg and tg.alias:
                                # If TradeGroup has a proper alias, use it
                                return tg.alias
                            elif tg and tg.name:
                                # If no alias but we have a TradeGroup name, extract clean part
                                return extract_clean_group_name(tg.name)
                            elif fallback_name:
                                # If no TradeGroup found, extract clean part from the raw MT5 group name
                                return extract_clean_group_name(fallback_name)
                            return ''

                        def extract_clean_group_name(group_name):
                            """Extract clean name from MT5 group path like 'demo\\KRSNA' -> 'KRSNA' """
                            if not group_name:
                                return ''
                            # Split by backslash or forward slash and get the last meaningful part
                            parts = group_name.replace('/', '\\').split('\\')
                            # Look for the main identifier (usually the last non-empty part)
                            for part in reversed(parts):
                                if part and not part.lower() in ['demo', 'real']:
                                    return part
                            # If no meaningful part found, return the last part
                            return parts[-1] if parts and parts[-1] else group_name

                        # TradingAccount.group_name may store either the TradeGroup.name or the group_id
                        if getattr(db_account, 'group_name', None):
                            group_identifier = db_account.group_name
                            tg = resolve_tradegroup_by_string(db_account.group_name)
                            if tg:
                                group_alias = get_clean_alias(tg, db_account.group_name)
                                # prefer group_id from model if present
                                group_identifier = tg.group_id or tg.name or group_identifier
                            else:
                                # No TradeGroup found, extract clean name from raw group name
                                group_alias = extract_clean_group_name(db_account.group_name)

                        # Fallback: if no group_name set on account, try querying MT5 for the account's group and map to TradeGroup
                        if not group_alias and not group_identifier:
                            try:
                                mt5_group = mt5_service.get_group_of(account_id)
                                if mt5_group:
                                    # try to find a TradeGroup matching the MT5 group string using resolver
                                    tg2 = resolve_tradegroup_by_string(mt5_group)
                                    if tg2:
                                        # Use clean alias extraction
                                        group_alias = get_clean_alias(tg2, mt5_group)
                                        group_identifier = tg2.group_id or tg2.name or mt5_group
                                    else:
                                        # no DB TradeGroup, extract clean name from MT5 group string
                                        group_alias = extract_clean_group_name(mt5_group)
                                        group_identifier = mt5_group
                            except Exception:
                                # non-fatal: MT5 manager unavailable or error; leave alias empty
                                pass
                    except Exception:
                        # non-fatal: leave alias empty
                        group_alias = ''
                    
                    # Add active account to list
                    accounts_data.append({
                        'account_id': account_id,
                        'account_name': db_account.account_name,
                        'account_type': db_account.account_type,
                        'leverage': str(mt5_info.get('leverage', db_account.leverage)),
                        'balance': float(mt5_info.get('balance', 0.00)),
                        'equity': float(mt5_info.get('equity', 0.00)),
                        'margin': float(mt5_info.get('margin', 0.00)),
                        'free_margin': float(mt5_info.get('free_margin', 0.00)),
                        'margin_level': float(mt5_info.get('margin_level', 0.00)),
                        'is_active': True,
                        'group_name': db_account.group_name or '',
                        'group_alias': group_alias,
                        'group_id': group_identifier,
                    })
                    
                    # Update DB record with latest MT5 info
                    for field in ['balance', 'equity', 'leverage']:
                        if field in mt5_info:
                            setattr(db_account, field, mt5_info[field])
                    db_account.is_active = True
                    db_account.save()
                    
                except Exception as e:
                    sync_errors.append(f"Error syncing account {account_id}: {str(e)}")
                    logger.error(f"Error processing account {account_id}: {str(e)}")
            
            # Prepare and cache response
            response_payload = {
                'success': True,
                'accounts': accounts_data,
                'mt5_status': 'connected',
                'sync_errors': sync_errors if sync_errors else None
            }
            try:
                cache.set(cache_key, response_payload, timeout=2)
            except Exception:
                logger.debug('Failed to set cache for user trading accounts', exc_info=True)

            return Response(response_payload, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching trading accounts: {str(e)}")
            return Response({
                'success': False,
                'message': str(e),
                'accounts': [],
                'mt5_status': 'error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request):
        """Delete inactive trading accounts for the current user"""
        try:
            # Get inactive accounts
            inactive_accounts = TradingAccount.objects.filter(
                user=request.user,
                is_active=False
            )
            
            if not inactive_accounts.exists():
                return Response({
                    'success': False,
                    'message': 'No inactive accounts found to delete'
                }, status=status.HTTP_404_NOT_FOUND)

            # Log the accounts to be deleted
            account_ids = list(inactive_accounts.values_list('account_id', flat=True))
            logger.info(f"Deleting inactive accounts for user {request.user.id}: {account_ids}")

            # Delete the accounts
            deletion_count = inactive_accounts.delete()[0]
            
            return Response({
                'success': True,
                'message': f'Successfully deleted {deletion_count} inactive accounts',
                'deleted_accounts': account_ids
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error deleting inactive accounts: {str(e)}")
            return Response({
                'success': False,
                'message': f'Failed to delete inactive accounts: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class StatsOverviewView(LoginRequiredMixin, View):
    def get(self, request):
        try:
            # TODO: Implement actual stats retrieval
            return JsonResponse({
                'success': True,
                'data': {
                    'total_balance': 10000.00,
                    'total_equity': 10050.00,
                    'total_profit': 50.00,
                    'open_positions': 2,
                    'pending_withdrawals': 0
                }
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class RecentTransactionsView(LoginRequiredMixin, View):
    def get(self, request):
        try:
            # TODO: Implement actual transactions retrieval
            return JsonResponse({
                'success': True,
                'data': {
                    'transactions': []  # Add sample transactions here
                }
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class RemoveSpecificAccountsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Remove specific trading accounts"""
        try:
            account_ids = request.data.get('account_ids', [])
            if not account_ids:
                return Response({
                    'success': False,
                    'message': 'No account IDs provided'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            mt5_service = MT5ManagerActions()
            removed_accounts = []
            failed_accounts = []
            
            for account_id in account_ids:
                try:
                    # First try to delete from MT5 if it exists
                    try:
                        if mt5_service.delete_account(account_id):
                            logger.info(f"Successfully deleted MT5 account: {account_id}")
                        else:
                            logger.warning(f"Account {account_id} not found in MT5 or already deleted")
                    except Exception as mt5_error:
                        logger.error(f"Error deleting MT5 account {account_id}: {str(mt5_error)}")
                    
                    # Then delete from database
                    account = TradingAccount.objects.filter(
                        user=request.user,
                        account_id=account_id
                    ).first()
                    
                    if account:
                        account.delete()
                        removed_accounts.append(account_id)
                        logger.info(f"Successfully removed account {account_id} from database")
                    else:
                        failed_accounts.append(account_id)
                        logger.warning(f"Account {account_id} not found in database")
                        
                except Exception as e:
                    logger.error(f"Error removing account {account_id}: {str(e)}")
                    failed_accounts.append(account_id)
            
            # Prepare response message
            if removed_accounts and failed_accounts:
                message = f"Successfully removed accounts: {', '.join(map(str, removed_accounts))}. Failed to remove: {', '.join(map(str, failed_accounts))}"
            elif removed_accounts:
                message = f"Successfully removed accounts: {', '.join(map(str, removed_accounts))}"
            else:
                message = f"Failed to remove any accounts. Failed attempts: {', '.join(map(str, failed_accounts))}"
            
            return Response({
                'success': bool(removed_accounts),
                'message': message,
                'removed_accounts': removed_accounts,
                'failed_accounts': failed_accounts
            })
            
        except Exception as e:
            logger.error(f"Error in remove_specific_accounts: {str(e)}")
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class TradingAccountHistoryView(APIView):
    """
    API to fetch comprehensive history for a trading account including transactions and positions.
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, account_id):
        try:
            logger.info(f"Fetching history for account_id: {account_id}, user: {request.user.id}")
            
            # Verify account access: allow owner, staff, parent IB, or MAM investor
            account = None
            try:
                account = TradingAccount.objects.get(account_id=account_id, user=request.user)
           
            except TradingAccount.DoesNotExist:
                try:
                    possible_account = TradingAccount.objects.get(account_id=account_id)
                    # Allow staff
                    if getattr(request.user, 'is_staff', False):
                        account = possible_account
                        logger.debug(f"Staff user {request.user.id} accessing account {account.account_id}")
                    else:
                        # Allow if requesting user is parent IB of the account owner
                        account_owner = getattr(possible_account, 'user', None)
                        parent_ib = getattr(account_owner, 'parent_ib', None) if account_owner is not None else None
                        if parent_ib is not None and getattr(parent_ib, 'id', None) == getattr(request.user, 'id', None):
                            account = possible_account
                            logger.debug(f"IB parent {request.user.id} accessing child account {account.account_id}")
                        else:
                            # Check MAM investment relationship: user has an investment account linked to this manager
                            try:
                                investment_account = TradingAccount.objects.get(
                                    user=request.user,
                                    account_type='mam_investment',
                                    mam_master_account__account_id=account_id
                                )
                                account = investment_account.mam_master_account
                                logger.debug(f"Found MAM manager account through investment: {account.account_id}")
                            except TradingAccount.DoesNotExist:
                                logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                                return Response({'error': 'Account not found or you do not have permission to access it'}, status=status.HTTP_404_NOT_FOUND)
                except TradingAccount.DoesNotExist:
                    logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                    return Response({'error': 'Account not found or you do not have permission to access it'}, status=status.HTTP_404_NOT_FOUND)
            
            # Get query parameters for filtering and pagination
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
            transaction_type = request.query_params.get('type', None)  # 'deposit', 'withdrawal', 'credit_in', 'credit_out'
            date_from = request.query_params.get('date_from', None)
            date_to = request.query_params.get('date_to', None)
            include_mt5_deals = request.query_params.get('include_mt5_deals', 'true').lower() == 'true'
            
            # Build transaction query for database transactions
            transactions_query = Transaction.objects.filter(
                trading_account=account
            ).exclude(status='pending').order_by('-created_at')
            
            # Apply filters
            if transaction_type:
                transactions_query = transactions_query.filter(transaction_type=transaction_type)
            
            if date_from:
                from datetime import datetime
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
                transactions_query = transactions_query.filter(created_at__date__gte=date_from_obj)
                
            if date_to:
                from datetime import datetime
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
                transactions_query = transactions_query.filter(created_at__date__lte=date_to_obj)
            
            # Get database transactions
            db_transactions = list(transactions_query)
            
            # Get MT5 deals if requested
            mt5_transactions = []
            if include_mt5_deals:
                try:
                    from adminPanel.mt5.services import MT5ManagerActions
                    mt5 = MT5ManagerActions()
                    
                    # Determine date range for MT5 deals
                    import time
                    from datetime import datetime, timedelta
                    
                    if date_from and date_to:
                        from_date = datetime.strptime(date_from, '%Y-%m-%d')
                        to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                    elif date_from:
                        from_date = datetime.strptime(date_from, '%Y-%m-%d')
                        to_date = datetime.now()
                    elif date_to:
                        from_date = datetime.now() - timedelta(days=365)  # Default to last year
                        to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                    else:
                        # Default to last 90 days
                        from_date = datetime.now() - timedelta(days=90)
                        to_date = datetime.now()
                    
                    # Get all deals from MT5
                    deals = mt5.manager.DealRequest(int(account_id), int(from_date.timestamp()), int(to_date.timestamp()))
                    
                    if deals:
                        for deal in deals:
                            try:
                                # Convert MT5 deal to transaction-like format
                                deal_action = getattr(deal, 'Action', None)
                                deal_profit = getattr(deal, 'Profit', 0.0)
                                deal_comment = getattr(deal, 'Comment', '')
                                deal_time = getattr(deal, 'Time', 0)
                                deal_id = getattr(deal, 'Deal', None)
                                
                                # Filter for balance operations (Action == 2)
                                if deal_action == 2:
                                    # Determine transaction type based on profit
                                    if deal_profit > 0:
                                        trans_type = 'deposit_trading'
                                        type_display = 'Deposit'
                                    elif deal_profit < 0:
                                        trans_type = 'withdraw_trading'
                                        type_display = 'Withdrawal'
                                    else:
                                        continue  # Skip zero amounts
                                    
                                    # Filter by transaction type if specified
                                    if transaction_type:
                                        if transaction_type == 'deposit' and trans_type != 'deposit_trading':
                                            continue
                                        if transaction_type == 'withdrawal' and trans_type != 'withdraw_trading':
                                            continue
                                    
                                    # Convert MT5 timestamp to datetime
                                    try:
                                        from django.utils import timezone as django_timezone
                                        deal_datetime = datetime.fromtimestamp(deal_time) if deal_time else datetime.now()
                                        # Make timezone-aware to match Django model datetimes
                                        if deal_datetime.tzinfo is None:
                                            deal_datetime = django_timezone.make_aware(deal_datetime)
                                    except (ValueError, OSError):
                                        deal_datetime = django_timezone.now()
                                    
                                    # Create pseudo-transaction object for MT5 deal
                                    mt5_transaction = {
                                        'id': f"mt5_{deal_id}",
                                        'transaction_type': trans_type,
                                        'amount': abs(deal_profit),
                                        'description': f"MT5 {type_display}: {deal_comment}" if deal_comment else f"MT5 {type_display}",
                                        'status': 'approved',
                                        'created_at': deal_datetime,
                                        'approved_at': deal_datetime,
                                        'source': 'MT5 Server',
                                        'user': account.user.email if account.user else 'Unknown',
                                        'approved_by': 'MT5 System',
                                        'is_mt5_deal': True,
                                        'deal_id': deal_id,
                                        'mt5_comment': deal_comment,
                                    }
                                    
                                    mt5_transactions.append(mt5_transaction)
                                    
                            except Exception as deal_error:
                                logger.warning(f"Error processing MT5 deal: {deal_error}")
                                continue
                                
                except Exception as mt5_error:
                    logger.warning(f"Error fetching MT5 deals: {mt5_error}")
                    mt5_transactions = []
            
            # Combine and sort all transactions
            all_transactions = []
            
            # Add database transactions
            for tx in db_transactions:
                all_transactions.append({
                    'id': tx.id,
                    'transaction_type': tx.transaction_type,
                    'amount': float(tx.amount),
                    'description': tx.description or '',
                    'status': tx.status,
                    'created_at': tx.created_at,
                    'approved_at': tx.approved_at,
                    'source': tx.source or 'Database',
                    'user': tx.user.email if tx.user else 'Unknown',
                    'approved_by': tx.approved_by.email if tx.approved_by else '',
                    'is_mt5_deal': False,
                })
            
            # Add MT5 transactions
            all_transactions.extend(mt5_transactions)
            
            # Sort by date (newest first)
            all_transactions.sort(key=lambda x: x['created_at'], reverse=True)
            
            # Paginate combined results
            from django.core.paginator import Paginator
            paginator = Paginator(all_transactions, page_size)
            transactions_page = paginator.get_page(page)
            
            # Format transactions for serialization
            paginated_transactions = []
            for tx in transactions_page.object_list:
                paginated_transactions.append({
                    'id': tx['id'],
                    'transaction_type': tx['transaction_type'],
                    'amount': f"{tx['amount']:.2f}",
                    'description': tx['description'],
                    'status': tx['status'],
                    'created_at': tx['created_at'].isoformat() if hasattr(tx['created_at'], 'isoformat') else str(tx['created_at']),
                    'approved_at': tx['approved_at'].isoformat() if tx['approved_at'] and hasattr(tx['approved_at'], 'isoformat') else (str(tx['approved_at']) if tx['approved_at'] else ''),
                    'source': tx['source'],
                    'user': tx['user'],
                    'approved_by': tx['approved_by'],
                    'is_mt5_deal': tx['is_mt5_deal'],
                })
            
            # Get account summary from MT5 if available
            account_summary = {}
            try:
                _mt5 = get_mt5_service()
                account_info = _mt5.get_account_info(account_id)
                if account_info:
                    account_summary = {
                        'balance': account_info.get('balance', 0.0),
                        'equity': account_info.get('equity', 0.0),
                        'margin': account_info.get('margin', 0.0),
                        'free_margin': account_info.get('margin_free', 0.0),
                        'profit': account_info.get('profit', 0.0),
                    }
                else:
                    # Fallback to database values
                    account_summary = {
                        'balance': float(account.balance or 0.0),
                        'equity': float(account.balance or 0.0),
                        'margin': 0.0,
                        'free_margin': float(account.balance or 0.0),
                        'profit': 0.0,
                    }
            except Exception as mt5_error:
                logger.warning(f"MT5 account summary lookup failed: {mt5_error}")
                # Fallback to database values
                account_summary = {
                    'balance': float(account.balance or 0.0),
                    'equity': float(account.balance or 0.0), 
                    'margin': 0.0,
                    'free_margin': float(account.balance or 0.0),
                    'profit': 0.0,
                }
            
            # Get open positions from MT5 if available
            positions = []
            try:
                _mt5 = get_mt5_service()
                positions_data = _mt5.get_positions(account_id)
                if positions_data:
                    positions = [{
                        'ticket': pos.get('ticket', ''),
                        'symbol': pos.get('symbol', ''),
                        'type': 'Buy' if pos.get('type', 0) == 0 else 'Sell',
                        'volume': pos.get('volume', 0.0),
                        'open_price': pos.get('price_open', 0.0),
                        'current_price': pos.get('price_current', 0.0),
                        'profit': pos.get('profit', 0.0),
                        'swap': pos.get('swap', 0.0),
                        'time_open': pos.get('time', ''),
                    } for pos in positions_data]
            except Exception as mt5_error:
                logger.warning(f"MT5 positions lookup failed: {mt5_error}")
                positions = []
            
            return Response({
                'account_summary': account_summary,
                'transactions': {
                    'results': paginated_transactions,
                    'count': paginator.count,
                    'page': page,
                    'total_pages': paginator.num_pages,
                    'has_next': transactions_page.has_next(),
                    'has_previous': transactions_page.has_previous(),
                    'mt5_deals_included': include_mt5_deals,
                    'mt5_deals_count': len(mt5_transactions),
                    'db_transactions_count': len(db_transactions),
                },
                'positions': positions,
                'account_info': {
                    'account_id': account.account_id,
                    'account_type': account.account_type,
                    'leverage': account.leverage,
                    'status': account.status,
                    'currency': 'USD'
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching account history: {e}")
            return Response({
                'error': f'Error fetching account history: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch') 
class TradingAccountPositionsView(APIView):
    """
    API to fetch open positions for a trading account.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, account_id):
        try:
            logger.info(f"Fetching positions for account_id: {account_id}, user: {request.user.id}")
            
            # Verify account access: allow owner, staff, parent IB, or MAM investor
            account = None
            try:
                account = TradingAccount.objects.get(account_id=account_id, user=request.user)
   
            except TradingAccount.DoesNotExist:
                try:
                    possible_account = TradingAccount.objects.get(account_id=account_id)
                    # Allow staff
                    if getattr(request.user, 'is_staff', False):
                        account = possible_account
                        logger.debug(f"Staff user {request.user.id} accessing account {account.account_id}")
                    else:
                        # Allow if requesting user is parent IB of the account owner
                        account_owner = getattr(possible_account, 'user', None)
                        parent_ib = getattr(account_owner, 'parent_ib', None) if account_owner is not None else None
                        if parent_ib is not None and getattr(parent_ib, 'id', None) == getattr(request.user, 'id', None):
                            account = possible_account
                            logger.debug(f"IB parent {request.user.id} accessing child account {account.account_id}")
                        else:
                            # Check MAM investment relationship
                            try:
                                investment_account = TradingAccount.objects.get(
                                    user=request.user,
                                    account_type='mam_investment',
                                    mam_master_account__account_id=account_id
                                )
                                account = investment_account.mam_master_account
                                logger.debug(f"Found MAM manager account through investment: {account.account_id}")
                            except TradingAccount.DoesNotExist:
                                logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                                return Response({'error': 'Account not found or you do not have permission to access it'}, status=status.HTTP_404_NOT_FOUND)
                except TradingAccount.DoesNotExist:
                    logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                    return Response({'error': 'Account not found or you do not have permission to access it'}, status=status.HTTP_404_NOT_FOUND)
            
            # Get positions from MT5
            positions = []
            try:
                _mt5 = get_mt5_service()
                positions_data = _mt5.get_positions(account_id)
                if positions_data:
                    positions = [{
                        'ticket': pos.get('ticket', ''),
                        'symbol': pos.get('symbol', ''),
                        'type': 'Buy' if pos.get('type', 0) == 0 else 'Sell',
                        'volume': pos.get('volume', 0.0),
                        'open_price': pos.get('price_open', 0.0),
                        'current_price': pos.get('price_current', 0.0),
                        'profit': pos.get('profit', 0.0),
                        'swap': pos.get('swap', 0.0),
                        'commission': pos.get('commission', 0.0),
                        'time_open': pos.get('time', ''),
                        'comment': pos.get('comment', ''),
                    } for pos in positions_data]
                    
            except Exception as mt5_error:
                logger.warning(f"MT5 positions lookup failed: {mt5_error}")
                positions = []
            
            return Response({
                'positions': positions,
                'count': len(positions)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching positions: {e}")
            return Response({
                'error': f'Error fetching positions: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class TradingAccountTransactionsView(APIView):
    """
    API to fetch transaction history for a specific trading account.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, account_id):
        try:
            logger.info(f"Fetching transactions for account_id: {account_id}, user: {request.user.id}")
            
            # Verify account access: allow owner, staff, parent IB, or MAM investor
            account = None
            try:
                account = TradingAccount.objects.get(account_id=account_id, user=request.user)

            except TradingAccount.DoesNotExist:
                try:
                    possible_account = TradingAccount.objects.get(account_id=account_id)
                    # Allow staff
                    if getattr(request.user, 'is_staff', False):
                        account = possible_account
                        logger.debug(f"Staff user {request.user.id} accessing account {account.account_id}")
                    else:
                        # Allow if requesting user is parent IB of the account owner
                        account_owner = getattr(possible_account, 'user', None)
                        parent_ib = getattr(account_owner, 'parent_ib', None) if account_owner is not None else None
                        if parent_ib is not None and getattr(parent_ib, 'id', None) == getattr(request.user, 'id', None):
                            account = possible_account
                            logger.debug(f"IB parent {request.user.id} accessing child account {account.account_id}")
                        else:
                            # Check MAM investment relationship
                            try:
                                investment_account = TradingAccount.objects.get(
                                    user=request.user,
                                    account_type='mam_investment',
                                    mam_master_account__account_id=account_id
                                )
                                account = investment_account.mam_master_account
                                logger.debug(f"Found MAM manager account through investment: {account.account_id}")
                            except TradingAccount.DoesNotExist:
                                logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                                return Response({'error': 'Account not found or you do not have permission to access it'}, status=status.HTTP_404_NOT_FOUND)
                except TradingAccount.DoesNotExist:
                    logger.warning(f"Account {account_id} not found or not accessible by user {request.user.id}")
                    return Response({'error': 'Account not found or you do not have permission to access it'}, status=status.HTTP_404_NOT_FOUND)
            
            # Get query parameters
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
            transaction_type = request.query_params.get('type', None)
            status_filter = request.query_params.get('status', None)
            date_from = request.query_params.get('date_from', None)
            date_to = request.query_params.get('date_to', None)
            
            # Build query
            transactions = Transaction.objects.filter(
                trading_account=account
            ).order_by('-created_at')
            
            # Apply filters
            if transaction_type:
                transactions = transactions.filter(transaction_type=transaction_type)
                
            if status_filter:
                transactions = transactions.filter(status=status_filter)
            else:
                # Exclude pending by default unless explicitly requested
                transactions = transactions.exclude(status='pending')
            
            if date_from:
                from datetime import datetime
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
                transactions = transactions.filter(created_at__date__gte=date_from_obj)
                
            if date_to:
                from datetime import datetime
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
                transactions = transactions.filter(created_at__date__lte=date_to_obj)
            
            # Paginate
            from django.core.paginator import Paginator
            paginator = Paginator(transactions, page_size)
            transactions_page = paginator.get_page(page)
            
            # Serialize
            serializer = TransactionSerializer(transactions_page.object_list, many=True)
            
            return Response({
                'results': serializer.data,
                'count': paginator.count,
                'page': page,
                'total_pages': paginator.num_pages,
                'has_next': transactions_page.has_next(),
                'has_previous': transactions_page.has_previous(),
                'page_size': page_size
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching transactions: {e}")
            return Response({
                'error': f'Error fetching transactions: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
