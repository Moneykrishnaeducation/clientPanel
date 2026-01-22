from rest_framework.views import APIView
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from adminPanel.authentication import BlacklistCheckingJWTAuthentication
from adminPanel.api_decorators import require_admin_approval
from django.conf import settings
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator
import os
import environ

env = environ.Env()
environ.Env.read_env(os.path.join(settings.BASE_DIR, '.env'))

REFERRAL_CLIENT_URLS = getattr(settings, 'REFERRAL_CLIENT_URLS', env('REFERRAL_CLIENT_URLS', default='https://client.localhost/register,https://client.vtifx/register,https://admin.localhost/register,https://admin.vtifx/register').split(','))

class IBReferralLinkView(APIView):
    """
    API endpoint to return the IB referral link for the authenticated user.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user or not user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        if not getattr(user, "IB_status", False):
            return Response({"error": "User is not an approved IB"}, status=status.HTTP_403_FORBIDDEN)
        if not user.referral_code:
            # Generate and save referral code if missing (should be rare)
            user.referral_code = user.generate_referral_code()
            user.save()
        # Use the first allowed client URL from settings or .env
        base_url = getattr(settings, 'REFERRAL_BASE_URL', None)
        if not base_url:
            base_url = REFERRAL_CLIENT_URLS[0]
        referral_link = f"{base_url}?ref={user.referral_code}"
        return Response({"referral_link": referral_link, "referral_code": user.referral_code}, status=status.HTTP_200_OK)
from adminPanel.mt5.services import MT5ManagerActions
from django.db import transaction
from django.core.exceptions import ValidationError
from django.utils.timezone import now
from adminPanel.models import CustomUser, TradingAccount, ActivityLog, Transaction, DemoAccount, CommissionTransaction, IBRequest
from adminPanel.models import BankDetailsRequest
from adminPanel.serializers import *
from adminPanel.views.views import get_client_ip
from adminPanel.EmailSender import EmailSender
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.shortcuts import get_object_or_404
from rest_framework.parsers import MultiPartParser, FormParser
from ..models import BankDetails, UserDocument
from ..serializers import BankDetailsSerializer
import logging
from ..models import BankDetails, UserDocument
from ..serializers import BankDetailsSerializer

logger = logging.getLogger(__name__)

class PropTradingAccountsView(APIView):
    """
    API View to fetch all proprietary trading accounts of the authenticated user.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            
            prop_accounts = TradingAccount.objects.filter(
                user=request.user, 
                account_type="prop"
            )

            if not prop_accounts.exists():
                return Response(
                    {"message": "No proprietary trading accounts found."},
                    status=status.HTTP_200_OK
                )

            serializer = TradingAccountSerializer(prop_accounts, many=True)

            
            enhanced_data = []
            mt5action = MT5ManagerActions()
            for account in prop_accounts:
                enhanced_data.append({
                    "username": (account.user.first_name + account.user.last_name),
                    "account_id": account.account_id,
                    "package": account.package.name,
                    "email": account.user.email,
                    "approvedOn": account.approved_at,
                    "status": account.status,
                    "balance": mt5action.get_balance(int(account.account_id)),
                    "equity": mt5action.get_equity(int(account.account_id)),
                    "profit": mt5action.total_account_profit(int(account.account_id)),
                    "stopout": account.package.total_tradable_fund - account.package.max_cutoff,
                    "target": account.package.total_tradable_fund + account.package.target,
                })

            return Response(enhanced_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
class ToggleInvestorCopyView(APIView):
    """
    API endpoint to toggle the 'investor_allow_copy' status for an investor.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, account_id):
        import logging
        logger = logging.getLogger(__name__)
        try:
            # Find the investor account by account_id, ensuring the manager owns the master account
            investor = get_object_or_404(
                TradingAccount, 
                account_id=account_id, 
                account_type="mam_investment",
                mam_master_account__user=request.user,
                mam_master_account__account_type="mam"
            )
            investor.manager_allow_copy = not investor.manager_allow_copy

            # Check for mam_master_account before proceeding
            if investor.manager_allow_copy:
                if not investor.mam_master_account or not getattr(investor.mam_master_account, 'account_id', None):
                    logger.error(f"MAM master account missing for investor {investor.account_id}")
                    return Response({"error": "MAM master account is not set for this investor."}, status=status.HTTP_400_BAD_REQUEST)
                logger.info(f"Enabling copy for investor {investor.account_id} with master {investor.mam_master_account.account_id}")
                result = MT5ManagerActions().start_mam_copy(int(investor.account_id), int(investor.mam_master_account.account_id))
                if result:
                    investor.save()
                    return Response(
                        {
                            "account_id": investor.account_id,
                            "manager_allow_copy": investor.manager_allow_copy,
                            "message": f"Copying {'enabled' if investor.manager_allow_copy else 'disabled'} successfully.",
                        },
                        status=status.HTTP_200_OK,
                    )
                else:
                    logger.error(f"start_mam_copy failed for investor {investor.account_id} and master {investor.mam_master_account.account_id}")
                    return Response({"error": "Failed to start MAM copy on MT5."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            else:
                logger.info(f"Disabling copy for investor {investor.account_id}")
                result = MT5ManagerActions().pause_mam_copy(int(investor.account_id))
                if result:
                    investor.save()
                    ActivityLog.objects.create(
                        user=request.user,
                        activity=(
                            f"{'Enabled' if investor.manager_allow_copy else 'Disabled'} copying for "
                            f"MAM Investment Account with ID {investor.account_id}."
                        ),
                        ip_address=get_client_ip(request),
                        endpoint=request.path,
                        activity_type="update",
                        activity_category="client",
                        user_agent=request.META.get("HTTP_USER_AGENT", ""),
                        timestamp=now(),
                        related_object_id=investor.id,
                        related_object_type="MAMInvestmentAccount"
                    )
                    return Response(
                        {
                            "account_id": investor.account_id,
                            "manage_allow_copy": investor.manager_allow_copy,
                            "message": f"Copying {'enabled' if investor.manager_allow_copy else 'disabled'} successfully.",
                        },
                        status=status.HTTP_200_OK,
                    )
                else:
                    logger.error(f"pause_mam_copy failed for investor {investor.account_id}")
                    return Response({"error": "Failed to pause MAM copy on MT5."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except TradingAccount.DoesNotExist:
            logger.error(f"Investor not found for account_id {account_id}")
            return Response(
                {"error": "Investor not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            logger.exception(f"Exception in ToggleInvestorCopyView for account_id {account_id}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
            
class StatsOverviewView(APIView):
    """
    API endpoint to fetch client statistics overview in the format expected by frontend.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # print(f"[StatsOverviewView] Request from user: {request.user.email} (ID: {request.user.id}, IB_status: {request.user.IB_status})")
            
            def safe_get_real_balance():
                try:
                    mt5action = MT5ManagerActions()
                    account_ids = [i.account_id for i in TradingAccount.objects.filter(user=request.user, account_type='standard')]               
                    real_balance = sum([mt5action.get_balance(account_id) for account_id in account_ids])
                    return real_balance
                except Exception:
                    return 0.0

            def safe_get_total_deposits():
                try:
                    return sum([i.amount for i in Transaction.objects.filter(trading_account__user=request.user, transaction_type = "deposit_trading", status='approved')])
                except Exception:
                    return 0.0

            def safe_get_mam_investments():
                try:
                    mt5action = MT5ManagerActions()
                    
                    # Get all mam_investment accounts for the user
                    mam_investments = TradingAccount.objects.filter(
                        user=request.user,
                        account_type='mam_investment'
                    )
                    
                    # Sum the amount_invested (which is the balance from MT5)
                    total_invested = 0.0
                    for investment in mam_investments:
                        balance = mt5action.get_balance(investment.account_id)
                        total_invested += float(balance) if balance else 0.0
                        print(f"[safe_get_mam_investments] Investment {investment.account_id}: balance = {balance}")
                    
                    print(f"[safe_get_mam_investments] Total invested in MAM accounts: {total_invested}")
                    return float(total_invested) if total_invested else 0.0
                except Exception as e:
                    print(f"Error in safe_get_mam_investments: {e}")
                    import traceback
                    traceback.print_exc()
                    return 0.0

            def safe_get_mam_managed_funds():
                try:
                    mt5action = MT5ManagerActions()
                    
                    # Get all mam (manager) accounts owned by this user
                    # These are accounts that THIS user is managing/running
                    mam_accounts = TradingAccount.objects.filter(
                        user=request.user,
                        account_type='mam'
                    )
                    
                    print(f"[safe_get_mam_managed_funds] Found {mam_accounts.count()} MAM (manager) accounts for user")
                    
                    # Sum the balance of all MAM accounts managed by this user
                    total_balance = 0.0
                    for acc in mam_accounts:
                        balance = mt5action.get_balance(acc.account_id)
                        total_balance += float(balance) if balance else 0.0
                        print(f"[safe_get_mam_managed_funds] MAM Account {acc.account_id}: balance = {balance}")
                    
                    print(f"[safe_get_mam_managed_funds] Total MAM managed funds: {total_balance}")
                    return float(total_balance) if total_balance else 0.0
                    
                except Exception as e:
                    print(f"Error in safe_get_mam_managed_funds: {e}")
                    import traceback
                    traceback.print_exc()
                    return 0.0

            # Safely get user stats with fallbacks
            try:
                total_clients = len(request.user.get_all_clients()) if hasattr(request.user, 'get_all_clients') else 0
            except Exception:
                total_clients = 0

            try:
                total_earnings = float(request.user.total_earnings)
            except Exception:
                total_earnings = 0.0

            try:
                total_withdrawals = float(request.user.total_commission_withdrawals)
            except Exception:
                total_withdrawals = 0.0

            try:
                # Count only standard trading accounts
                live_accounts = TradingAccount.objects.filter(
                    user=request.user,
                    account_type='standard'
                ).count()
            except Exception:
                live_accounts = 0

            try:
                demo_accounts = DemoAccount.objects.filter(user=request.user).count()
            except Exception:
                demo_accounts = 0

            # Get direct clients count (level 1 only)
            try:
                direct_clients = request.user.direct_client_count if hasattr(request.user, 'direct_client_count') else 0
            except Exception:
                direct_clients = 0

            # Calculate current month earnings - exclude demo account commissions
            try:
                from django.utils import timezone
                from django.db.models import Sum
                current_date = timezone.now()
                current_month_earnings = CommissionTransaction.objects.filter(
                    ib_user=request.user,
                    created_at__year=current_date.year,
                    created_at__month=current_date.month
                ).exclude(
                    client_trading_account__account_type='demo'
                ).aggregate(total=Sum('commission_to_ib'))['total'] or 0.0
            except Exception:
                current_month_earnings = 0.0

            # Get earnings per client data with name and email - exclude demo account commissions
            try:
                earnings_per_client = CommissionTransaction.objects.filter(
                    ib_user=request.user
                ).exclude(
                    client_trading_account__account_type='demo'
                ).values(
                    'client_user__first_name',
                    'client_user__last_name', 
                    'client_user__email'
                ).annotate(
                    total_commission=Sum('commission_to_ib')
                ).order_by('-total_commission')[:10]  # Top 10 clients by commission
                
                # Format the data for frontend
                formatted_earnings_per_client = []
                for item in earnings_per_client:
                    if item['total_commission'] and item['total_commission'] > 0:
                        name = f"{item['client_user__first_name'] or ''} {item['client_user__last_name'] or ''}".strip()
                        if not name:
                            name = item['client_user__email'].split('@')[0] if item['client_user__email'] else 'Unknown'
                        
                        formatted_earnings_per_client.append({
                            'name': name,
                            'email': item['client_user__email'] or '',
                            'total_commission': float(item['total_commission'])
                        })
            except Exception as e:
                print(f"Error getting earnings per client: {e}")
                formatted_earnings_per_client = []

            # Get monthly earnings data - exclude demo account commissions
            try:
                from django.db.models.functions import ExtractMonth, ExtractYear
                monthly_earnings = CommissionTransaction.objects.filter(
                    ib_user=request.user
                ).exclude(
                    client_trading_account__account_type='demo'
                ).annotate(
                    month=ExtractMonth('created_at'),
                    year=ExtractYear('created_at')
                ).values('month', 'year').annotate(
                    total=Sum('commission_to_ib')
                ).order_by('year', 'month')
                
                formatted_monthly_earnings = []
                for item in monthly_earnings:
                    if item['total'] and item['total'] > 0:
                        formatted_monthly_earnings.append({
                            'month': int(item['month']),
                            'year': int(item['year']),
                            'total': float(item['total'])
                        })
            except Exception as e:
                print(f"Error getting monthly earnings: {e}")
                formatted_monthly_earnings = []

            # Return the flat structure expected by the frontend
            stats_data = {
                "total_clients": total_clients,
                "direct_clients": direct_clients,  # Level 1 clients only
                "total_earnings": total_earnings,
                "total_withdrawals": total_withdrawals,
                "commission_balance": total_earnings - total_withdrawals,
                "current_month_earnings": float(current_month_earnings),  # Now properly calculated
                "live_accounts": live_accounts,
                "demo_accounts": demo_accounts,
                "real_balance": safe_get_real_balance(),
                "total_deposits": safe_get_total_deposits(),
                "mam_investments": safe_get_mam_investments(),
                "mam_managed_funds": safe_get_mam_managed_funds(),
                # Total volume traded (in lots) for this IB across commission transactions
                "total_volume_traded": 0.0,
                # Current month volume traded (lots)
                "current_month_volume_traded": 0.0,
                # Chart data with actual data
                "earnings_per_month": formatted_monthly_earnings,
                "earnings_per_client": formatted_earnings_per_client
            }

            # Try to compute total_volume_traded from CommissionTransaction lot_size/volume
            # Exclude demo account commissions
            try:
                from django.db.models import Sum
                total_vol = CommissionTransaction.objects.filter(
                    ib_user=request.user
                ).exclude(
                    client_trading_account__account_type='demo'
                ).aggregate(total=Sum('lot_size'))['total'] or 0.0
                stats_data['total_volume_traded'] = float(total_vol)
                print(f"[StatsOverviewView] total_volume_traded calculation successful: {total_vol}")
            except Exception as e:
                # leave default 0.0 if aggregation fails
                print(f"[StatsOverviewView] Error calculating total_volume_traded: {e}")
                import traceback
                traceback.print_exc()

            # Try to compute current_month_volume_traded for the current calendar month
            # Exclude demo account commissions
            try:
                from django.utils import timezone
                from django.db.models import Sum
                now = timezone.now()
                cur_vol = CommissionTransaction.objects.filter(
                    ib_user=request.user,
                    created_at__year=now.year,
                    created_at__month=now.month
                ).exclude(
                    client_trading_account__account_type='demo'
                ).aggregate(total=Sum('lot_size'))['total'] or 0.0
                stats_data['current_month_volume_traded'] = float(cur_vol)
                print(f"[StatsOverviewView] current_month_volume_traded calculation successful: {cur_vol} (Year: {now.year}, Month: {now.month})")
            except Exception as e:
                # leave default 0.0 if aggregation fails
                print(f"[StatsOverviewView] Error calculating current_month_volume_traded: {e}")
                import traceback
                traceback.print_exc()

            return Response(stats_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": "Failed to fetch stats overview", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

@method_decorator(cache_page(60), name='dispatch')  # Cache for 1 minute
class BasicUserInfoView(APIView):
    """
    Lightweight API endpoint for basic user info - loads very fast.
    Used for quick dashboard initialization without heavy calculations.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            return Response({
                "name": f"{user.first_name} {user.last_name}".strip() or user.username,
                "email": user.email,
                "role": getattr(user, 'manager_admin_status', 'Client').lower(),
                "is_ib": getattr(user, 'IB_status', False),
                "total_accounts": TradingAccount.objects.filter(user=user).count(),
                "total_demo_accounts": DemoAccount.objects.filter(user=user).count(),
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "Failed to fetch basic user info", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class IBStatusView(APIView):
    """
    API endpoint to check IB approval status and update it.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            
            # Check if user is authenticated
            if not user or not user.is_authenticated:
                return Response(
                    {"error": "Authentication required"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            
            # Get user role details
            ib_status = getattr(user, "IB_status", False)
            role = getattr(user, "role", None)
            is_manager = role == "manager"

            # Approve if IB_status is True (regardless of role), or if manager
            is_approved = ib_status
            if ib_status and not is_manager:
                user_type = "parent_ib"  # IB only
            elif is_manager and ib_status:
                user_type = "manager_with_ib"  # Manager with IB
            elif is_manager:
                user_type = "manager"  # Manager only
            else:
                user_type = "client"

            # Check for an existing IBRequest to report "pending" state back to client
            try:
                ib_request = IBRequest.objects.filter(user=user).first()
            except Exception:
                ib_request = None

            if ib_request and getattr(ib_request, 'status', None) == 'pending' and not is_approved:
                return Response({
                    "approved": False,
                    "status": "pending",
                    "user_type": user_type,
                    "has_ib_status": ib_status,
                    "has_manager_role": is_manager,
                    "message": "IB request pending approval"
                }, status=status.HTTP_200_OK)

            # If request exists and was explicitly approved/rejected, prefer that value
            if ib_request and getattr(ib_request, 'status', None) == 'rejected' and not is_approved:
                return Response({
                    "approved": False,
                    "status": "rejected",
                    "user_type": user_type,
                    "has_ib_status": ib_status,
                    "has_manager_role": is_manager,
                    "message": "IB request was rejected"
                }, status=status.HTTP_200_OK)

            return Response({
                "approved": is_approved,
                "status": "approved" if is_approved else "rejected",
                "user_type": user_type,
                "has_ib_status": ib_status,
                "has_manager_role": is_manager,
                "message": "User status retrieved successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": "Failed to fetch IB status", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class IBCommissionBalanceView(APIView):
    """
    API endpoint to fetch commission balance.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            # Safely get total earnings
            try:
                total_earnings = float(user.total_earnings)
            except Exception as e:
                print(f'Error getting total_earnings: {{e}}')
                total_earnings = 0.0
            # Safely get total withdrawals
            try:
                total_withdrawals = float(user.total_commission_withdrawals)
            except Exception as e:
                print(f'Error getting total_commission_withdrawals: {{e}}')
                total_withdrawals = 0.0
            withdrawable_balance = total_earnings - total_withdrawals
            return Response({
                "balance": withdrawable_balance,
                "withdrawable_balance": withdrawable_balance,
                "total_earnings": total_earnings,
                "total_withdrawals": total_withdrawals
            }, status=status.HTTP_200_OK)
        except Exception as e:
            print(f'Exception in IBCommissionBalanceView: {{e}}')
            return Response(
                {"error": "Failed to fetch commission balance", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class IBCommissionTransactionsView(APIView):
    """
    API endpoint to fetch commission transactions.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Include profit and position type/direction explicitly so frontend can show P/L and action
            # Exclude demo account commissions
            transactions = CommissionTransaction.objects.filter(
                ib_user=request.user
            ).exclude(
                client_trading_account__account_type='demo'
            ).order_by('-created_at').values(
                'position_id', 'client_user__email', 'client_trading_account__id', 'client_trading_account__account_id',
                'position_symbol', 'total_commission', 'commission_to_ib', 'lot_size', 'profit', 'position_type', 
                'position_direction', 'created_at', 'deal_ticket', 'mt5_close_time'
            )
            # Format for frontend
            # Prepare list of dicts
            data_list = [
                {
                    'position_id': t['position_id'],
                    'client_user': t['client_user__email'],
                    'client_trading_account': t['client_trading_account__account_id'],  # Use actual MT5 account number
                    'position_symbol': t['position_symbol'],
                    'total_commission': float(t.get('total_commission') or 0.0),
                    'amount': float(t.get('commission_to_ib') or 0.0),
                    # Provide volume/lot size so frontend can render it. Use 'position_volume' and 'volume' for compatibility.
                    'position_volume': float(t.get('lot_size')) if t.get('lot_size') is not None else None,
                    'volume': float(t.get('lot_size')) if t.get('lot_size') is not None else None,
                    # Include profit and action/side fields if available (use .get defensively)
                    'profit': float(t.get('profit')) if t.get('profit') is not None else 0.0,
                    'action': t.get('position_type') or t.get('position_direction') or 'N/A',
                    'created_at': t.get('created_at'),
                    # Include MT5 verification fields
                    'deal_ticket': t.get('deal_ticket'),
                    'mt5_close_time': t.get('mt5_close_time'),
                }
                for t in transactions
            ]

            # Pagination parameters
            page = request.GET.get('page')
            page_size = request.GET.get('page_size') or request.GET.get('page-size') or request.GET.get('limit')
            try:
                page_size = int(page_size) if page_size is not None else None
            except (ValueError, TypeError):
                page_size = None

            if page is not None and page_size:
                try:
                    page = int(page)
                except (ValueError, TypeError):
                    page = 1
                paginator = Paginator(data_list, page_size)
                try:
                    page_obj = paginator.page(page)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)

                response_data = {
                    'count': paginator.count,
                    'next': page_obj.has_next() and f"?page={page_obj.next_page_number()}&page_size={page_size}" or None,
                    'previous': page_obj.has_previous() and f"?page={page_obj.previous_page_number()}&page_size={page_size}" or None,
                    'results': list(page_obj.object_list),
                }
                return Response(response_data, status=status.HTTP_200_OK)

            return Response(data_list, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "Failed to fetch commission transactions", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class IBTransactionsView(APIView):
    """
    API endpoint to fetch IB withdrawal transactions.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Filter for commission withdrawal transactions for this user
            transactions = Transaction.objects.filter(
                user=request.user,
                transaction_type="commission_withdrawal"
            ).select_related('trading_account').order_by('-created_at')
            
            # Format for frontend with user, type, and comment fields
            data = [
                {
                    'id': t.id,
                    'amount': float(t.amount),
                    'status': t.status,
                    'created_at': t.created_at,
                    'trading_account': t.trading_account.account_id if t.trading_account else 'N/A',
                    'account_id': t.trading_account.account_id if t.trading_account else 'N/A',
                    'account_name': t.trading_account.account_name if t.trading_account else 'N/A',
                    'account_type': t.trading_account.account_type if t.trading_account else 'N/A',
                    'user': request.user.get_full_name() or request.user.email,
                    'comment': t.comment if hasattr(t, 'comment') and t.comment else 'Withdrawal Request',
                    'source': t.transaction_type,
                }
                for t in transactions
            ]

            return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": "Failed to fetch withdrawal transactions", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CreateUserView(APIView):
    permission_classes = [] 

    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = NewUserSignupSerializer(data=data)

        if serializer.is_valid():
            user = serializer.save()
            
            # Send welcome email
            EmailSender.send_welcome_email(user.email, f"{user.first_name} {user.last_name}")
            
            # Create activity log
            ActivityLog.objects.create(
                user=user,
                activity="New user registration",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now()
            )
            
            return Response(
                {"message": "User created successfully and welcome email sent."},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )



class InternalTransferView(APIView):
    """
    Handles internal transfers between trading accounts for the authenticated user.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = InternalTransferSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with transaction.atomic():
                from_account_id = serializer.validated_data['from_account_id']
                to_account_id = serializer.validated_data['to_account_id']
                amount = float(serializer.validated_data['amount'])
                description = serializer.validated_data.get('comment', 'Internal Transfer')

                # Get and validate accounts
                from_account = TradingAccount.objects.get(account_id=from_account_id, user=user)
                to_account = TradingAccount.objects.get(account_id=to_account_id, user=user)

                # Check account types
                if from_account.account_type == 'prop' or to_account.account_type == 'prop':
                    return Response(
                        {'error': 'Cannot transfer to or from proprietary trading accounts.'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Check sufficient balance
                if from_account.balance < amount:
                    return Response(
                        {'error': 'Insufficient balance in source account.'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Perform MT5 transfer
                mt5action = MT5ManagerActions()
                if not mt5action.internal_transfer(int(to_account_id), int(from_account_id), amount):
                    raise ValidationError('MT5 transfer failed')

                # Create transaction record
                transaction_obj = Transaction.objects.create(
                    user=user,
                    transaction_type='internal_transfer',
                    amount=amount,
                    description=description,
                    from_account=from_account,
                    to_account=to_account,
                    status='approved',
                    approved_by=user,
                    approved_at=now()
                )

                # Log activity
                ActivityLog.objects.create(
                    user=user,
                    activity=f"Internal transfer of ${amount} from account {from_account.account_id} to {to_account.account_id}",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="create",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=transaction_obj.id,
                    related_object_type="Transaction"
                )

                return Response({
                    'message': 'Transfer completed successfully',
                    'transaction_id': transaction_obj.id
                }, status=status.HTTP_200_OK)

        except TradingAccount.DoesNotExist:
            return Response(
                {'error': 'One or both accounts not found.'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except ValidationError as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': f'An unexpected error occurred: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request):
        """Get internal transfer history for the authenticated user"""
        user = request.user
        transfers = Transaction.objects.filter(
            user=user,
            transaction_type='internal_transfer'
        ).order_by('-created_at')
        
        serializer = TransactionSerializer(transfers, many=True)
        return Response(serializer.data)

@method_decorator(csrf_exempt, name='dispatch')
class UserProfileView(APIView):
    """API View to handle user profile operations"""
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get user profile details"""
        try:
            user = request.user
            # Get live and demo account counts
            live_accounts = TradingAccount.objects.filter(
                user=user, 
                account_type__in=['standard', 'basic', 'pro']
            ).count()
            demo_accounts = TradingAccount.objects.filter(
                user=user, 
                account_type='demo'
            ).count()

            # Prepare profile picture URL
            profile_pic_url = None
            if user.profile_pic:
                try:
                    # If profile_pic is a FieldFile, use its .url
                    profile_pic_url = request.build_absolute_uri(user.profile_pic.url)
                except Exception:
                    # Fallbacks: if it's stored as a name or absolute URL
                    pic_field = getattr(user, 'profile_pic', None)
                    pic_name = getattr(pic_field, 'name', None) or str(pic_field)
                    if pic_name and pic_name.startswith('http'):
                        profile_pic_url = pic_name
                    elif pic_name:
                        profile_pic_url = request.build_absolute_uri(f"{settings.MEDIA_URL}{pic_name}")

            data = {
                'name': f"{user.first_name} {user.last_name}".strip(),
                'email': user.email,
                'phone': user.phone_number,  # Changed from phone to phone_number
                'verification_status': getattr(user, 'verification_status', 'pending'),
                'id_status': 'approved' if user.id_proof_verified else 'pending',  # Use actual model field
                'live_accounts': live_accounts,
                'demo_accounts': demo_accounts,
                'user_id': user.user_id,  # This field exists in the model
                'country': user.country or '',  # Use direct model field with fallback
                'city': user.city or '',        # Use direct model field with fallback
                'address': user.address or '',    # Use direct model field with fallback
                'profile_pic': profile_pic_url,  # Include absolute profile picture URL
                'dob': str(user.dob) if hasattr(user, 'dob') and user.dob else '',  # Add date of birth
                'created_by': user.created_by.email if user.created_by else '',
                'parent_ib': user.parent_ib.email if user.parent_ib else '',
                'is_approved_by_admin': getattr(user, 'is_approved_by_admin', False),
            }
            return Response(data)
        except Exception as e:
            logger.error(f"Error fetching user profile: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to fetch profile details'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request):
        """Update user profile details"""
        try:
            user = request.user
            # Check if user is approved by admin
            if not user.is_approved_by_admin:
                return Response({
                    "error": "Your account has not been approved by the admin yet. Please wait for admin approval.",
                    "code": "user_not_approved"
                }, status=status.HTTP_403_FORBIDDEN)
            data = request.data

            # Update allowed fields using the correct field names
            allowed_fields = {
                'first_name': 'first_name',
                'last_name': 'last_name', 
                'phone': 'phone_number',  # Map frontend 'phone' to model's 'phone_number'
                'country': 'country',
                'city': 'city',
                'address': 'address'
            }

            # Update each field if provided in the request
            for frontend_field, model_field in allowed_fields.items():
                if frontend_field in data:
                    value = data[frontend_field]
                    # Ensure we're not setting empty strings for optional fields
                    if value or model_field in ['first_name', 'last_name']:  # Required fields can be updated even with empty string
                        setattr(user, model_field, value)
            
            user.save()
            logger.debug(f"Updated profile for user {user.email}")
            
            # Return the updated profile data
            return self.get(request)  # Reuse the get method to return updated data
            
        except Exception as e:
            logger.error(f"Error updating user profile: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to update profile details'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(csrf_exempt, name='dispatch')
class UserDocumentView(APIView):
    """
    API View for handling user document uploads and status.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def validate_file(self, file):
        """Validate file size and type"""
        # Validate file type
        valid_types = [
            'image/jpeg', 'image/png', 'image/jpg', 'application/pdf',
            'image/webp', 'image/heic', 'image/heif'
        ]
        
        if not hasattr(file, 'content_type'):
            return False, 'Invalid file format'
            
        if file.content_type not in valid_types:
            return False, f'Invalid file type: {file.content_type}. Allowed types: JPEG, PNG, PDF'
            
        # Validate file size (max 10MB)
        if file.size > 10 * 1024 * 1024:
            return False, 'File too large. Maximum size is 10MB'
            
        return True, None

    def get(self, request, document_type=None):
        """Get user documents or specific document type status"""
        try:
            
            # If document_type is specified, return only that document
            if document_type:
                document = UserDocument.objects.filter(
                    user=request.user,
                    document_type=document_type
                ).first()
                
                if not document:
                    return Response({
                        'status': 'pending',
                        'document_type': document_type
                    })
                
                return Response({
                    'status': document.status,
                    'document_type': document.document_type,
                    'document': document.document.url if document.document else None
                })
            
            # Otherwise return all documents
            documents = UserDocument.objects.filter(user=request.user)
            return Response([{
                'status': doc.status,
                'document_type': doc.document_type,
                'document': doc.document.url if doc.document else None
            } for doc in documents])

        except Exception as e:
            logger.error(f"Error fetching documents: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to fetch documents'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request, doc_type):
        """Upload new document"""
        try:
            logger.info(f"Starting document upload for user {request.user.id}, type: {doc_type}")
            logger.info(f"Request Files keys: {request.FILES.keys()}")
            
            # Input validation
            if doc_type not in ['identity', 'residence']:
                return Response(
                    {'error': 'Invalid document type'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if 'document' not in request.FILES:
                return Response(
                    {'error': 'No document file provided'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            document = request.FILES['document']
            logger.info(f"Received document: size={document.size}, type={getattr(document, 'content_type', 'unknown')}")
            
            # Validate file
            is_valid, error_message = self.validate_file(document)
            if not is_valid:
                return Response(
                    {'error': error_message},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                with transaction.atomic():
                    # Get or create document record
                    user_document, created = UserDocument.objects.get_or_create(
                        user=request.user,
                        document_type=doc_type,
                        defaults={'status': 'pending'}
                    )
                    logger.info(f"Document record {'created' if created else 'updated'}")

                    # Update existing document if not created
                    if not created and user_document.document:
                        logger.info("Deleting old document file")
                        # Delete old file if it exists
                        try:
                            user_document.document.delete(save=False)
                        except Exception as e:
                            logger.warning(f"Failed to delete old document: {e}")
                    
                    # Save new document
                    user_document.document = document
                    user_document.status = 'pending'
                    user_document.save()
                    logger.info(f"Document saved successfully at {user_document.document.path}")

                    # Log activity
                    ActivityLog.objects.create(
                        user=request.user,
                        activity=f"Uploaded {doc_type} document",
                        activity_type="upload",
                        activity_category="documents",
                        ip_address=get_client_ip(request),
                        endpoint=request.path
                    )
                    logger.info("Activity logged")

                    return Response({
                        'message': 'Document uploaded successfully',
                        'status': user_document.status,
                        'document_type': doc_type,
                        'document': user_document.document.url
                    }, status=status.HTTP_201_CREATED)

            except Exception as e:
                logger.error(f"Database error: {str(e)}", exc_info=True)
                return Response(
                    {'error': 'Failed to save document to database', 'details': str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            logger.error(f"Error uploading document: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to upload document', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
@method_decorator(csrf_exempt, name='dispatch')
class UserProfileChangeRequestsView(APIView):
    """
    API View for users to check their profile change request status.
    Returns only the current user's profile change requests.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get the current user's profile change requests"""
        try:
            from adminPanel.models import ChangeRequest
            
            # Get all profile change requests for the current user
            requests = ChangeRequest.objects.filter(user=request.user)
            
            def _file_url(field):
                try:
                    return field.url if field else None
                except Exception:
                    return None

            # Serialize the data
            data = []
            for req in requests:
                data.append({
                    'id': req.id,
                    'user_id': req.user_id,
                    'user_name': req.user.get_full_name() or req.user.username,
                    'email': req.user.email,
                    'requested_changes': getattr(req, 'requested_data', None),
                    'id_proof': _file_url(getattr(req, 'id_proof', None)),
                    'address_proof': _file_url(getattr(req, 'address_proof', None)),
                    'status': req.status,
                    'created_at': req.created_at,
                    'reviewed_at': req.reviewed_at
                })
            
            return Response(data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error fetching profile change requests: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to fetch profile change requests', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
@method_decorator(csrf_exempt, name='dispatch')
class UserProfileBannerView(APIView):
    """Handle profile banner upload and retrieval.

    GET: return the latest banner URL for the authenticated user if present.
    POST: accept form-data `banner` file, save under MEDIA_ROOT/profile_banners/,
          delete any previous banners for the user (by safe email prefix) and
          return the new absolute URL.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def _safe_prefix(self, user):
        safe_email = (user.email or str(user.id)).replace('@', '_at_').replace('.', '_')
        return safe_email

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            prefix = self._safe_prefix(user)
            banners_dir = os.path.join(settings.MEDIA_ROOT, 'profile_banners')
            if not os.path.exists(banners_dir):
                return Response({'banner_url': None}, status=status.HTTP_200_OK)

            candidates = [f for f in os.listdir(banners_dir) if f.startswith(prefix)]
            if not candidates:
                return Response({'banner_url': None}, status=status.HTTP_200_OK)

            # pick the most recent by modified time
            candidates_full = [(f, os.path.getmtime(os.path.join(banners_dir, f))) for f in candidates]
            candidates_full.sort(key=lambda x: x[1], reverse=True)
            chosen = candidates_full[0][0]
            rel_path = f'profile_banners/{chosen}'
            try:
                url = request.build_absolute_uri(f"{settings.MEDIA_URL}{rel_path}")
            except Exception:
                url = request.build_absolute_uri(f"{settings.MEDIA_URL}{rel_path}")
            return Response({'banner_url': url}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching banner: {e}", exc_info=True)
            return Response({'error': 'Failed to fetch banner'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, *args, **kwargs):
        try:
            if 'banner' not in request.FILES:
                return Response({'error': 'No banner file provided'}, status=status.HTTP_400_BAD_REQUEST)

            banner_file = request.FILES['banner']
            if not banner_file.content_type.startswith('image/'):
                return Response({'error': 'Invalid file type. Please upload an image.'}, status=status.HTTP_400_BAD_REQUEST)

            if banner_file.size > 8 * 1024 * 1024:
                return Response({'error': 'File too large. Maximum size is 8MB'}, status=status.HTTP_400_BAD_REQUEST)

            user = request.user
            prefix = self._safe_prefix(user)
            banners_dir = os.path.join(settings.MEDIA_ROOT, 'profile_banners')
            os.makedirs(banners_dir, exist_ok=True)

            # Remove previous banners for this user
            for fname in os.listdir(banners_dir):
                if fname.startswith(prefix):
                    try:
                        os.remove(os.path.join(banners_dir, fname))
                    except Exception:
                        pass

            file_extension = os.path.splitext(banner_file.name)[1] or '.jpg'
            unique_filename = f"{prefix}_{int(now().timestamp())}{file_extension}"
            file_path = os.path.join(banners_dir, unique_filename)
            with open(file_path, 'wb+') as dest:
                for chunk in banner_file.chunks():
                    dest.write(chunk)

            rel_path = f'profile_banners/{unique_filename}'
            try:
                url = request.build_absolute_uri(f"{settings.MEDIA_URL}{rel_path}")
            except Exception:
                url = request.build_absolute_uri(f"{settings.MEDIA_URL}{rel_path}")

            return Response({'message': 'Banner uploaded', 'banner_url': url}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception(f"Error uploading banner: {e}")
            return Response({'error': 'Failed to upload banner', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class UserBankDetailsView(APIView):
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user bank details"""
        try:
            bank_details = BankDetails.objects.filter(user=request.user).first()
            
            if not bank_details:
                return Response({})
            
            serializer = BankDetailsSerializer(bank_details)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error fetching bank details: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to fetch bank details'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def post(self, request):
        """Update bank details"""
        try:
            logger.debug(f"Updating bank details for user: {request.user.id}")
            logger.debug(f"Request data: {request.data}")
            
            # Convert empty strings to None
            data = {k: v.strip() if isinstance(v, str) else v for k, v in request.data.items()}
            data = {k: v if v else None for k, v in data.items()}
            
            bank_details = BankDetails.objects.filter(user=request.user).first()
            
            # Always update or create BankDetails
            data['user'] = request.user
            data['status'] = 'pending'
            bank_details, created = BankDetails.objects.update_or_create(
                user=request.user,
                defaults=data
            )
            serializer = BankDetailsSerializer(bank_details)

            # Create a BankDetailsRequest for admin review
            try:
                req = BankDetailsRequest.objects.create(
                    user=request.user,
                    bank_name=data.get('bank_name'),
                    account_number=data.get('account_number'),
                    branch_name=data.get('branch_name'),
                    ifsc_code=data.get('ifsc_code'),
                    status='PENDING'
                )
                logger.info(f"BankDetailsRequest created successfully: id={req.id}, user={req.user}, bank_name={req.bank_name}")
            except Exception as e:
                logger.error(f"Failed to create BankDetailsRequest: {e}", exc_info=True)

            try:
                ActivityLog.objects.create(
                    user=request.user,
                    activity="Added or updated bank details - pending admin approval",
                    activity_type="create" if created else "update"
                )
            except Exception as log_error:
                logger.warning(f"Failed to create activity log: {log_error}")

            return Response({
                'message': 'Bank details submitted successfully. Awaiting admin approval.',
                **serializer.data
            })
                
        except Exception as e:
            logger.error(f"Error updating bank details: {e}", exc_info=True)
            return Response(
                {'error': f'Failed to update bank details: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(csrf_exempt, name='dispatch')
class UserCryptoDetailsView(APIView):
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user crypto wallet details"""
        try:
            crypto_details = CryptoDetails.objects.filter(user=request.user).first()
            
            if not crypto_details:
                return Response({}, status=status.HTTP_200_OK)
            
            data = {
                'wallet_address': crypto_details.wallet_address,
                'currency': crypto_details.currency,
                'status': crypto_details.status,
                'created_at': crypto_details.created_at,
                'updated_at': crypto_details.updated_at
            }
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching crypto details for user {request.user.id}: {str(e)}")
            return Response(
                {'error': 'Failed to fetch crypto details', 'detail': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    def post(self, request):
        """Update or create user crypto details"""
        try:
            logger.debug(f"Updating crypto details for user: {request.user.id}")
            data = request.data
            
            # Validate required fields
            if 'wallet_address' not in data or not data['wallet_address'].strip():
                return Response(
                    {'error': 'Wallet address is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Get or create crypto details
            crypto_details, created = CryptoDetails.objects.get_or_create(
                user=request.user,
                defaults={
                    'wallet_address': data['wallet_address'].strip(),
                    'currency': data.get('currency', 'BTC'),  # Default to BTC if not specified
                    'status': 'pending'  # New records start as pending
                }
            )
            
            if not created:
                # Update existing record and reset status to pending
                crypto_details.wallet_address = data['wallet_address'].strip()
                if 'currency' in data:
                    crypto_details.currency = data['currency']
                crypto_details.status = 'pending'  # Reset to pending on any update
                crypto_details.save()
            
            try:
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"{'Created' if created else 'Updated'} crypto details - pending admin approval",
                    activity_type="create" if created else "update",
                    details="Crypto details awaiting admin approval"
                )
            except Exception as log_error:
                logger.warning(f"Failed to create activity log: {log_error}")
            
            logger.info(f"Successfully {'created' if created else 'updated'} crypto details for user: {request.user.id}")
            
            response_data = {
                'wallet_address': crypto_details.wallet_address,
                'currency': crypto_details.currency,
                'status': crypto_details.status,
                'created_at': crypto_details.created_at,
                'updated_at': crypto_details.updated_at
            }
            
            return Response({
                'message': f'Crypto details {"created" if created else "updated"} successfully. Awaiting admin approval.',
                **response_data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error updating crypto details for user {request.user.id}: {str(e)}")
            return Response(
                {'error': 'Failed to update crypto details', 'detail': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(csrf_exempt, name='dispatch')
class UserProfileImageView(APIView):
    """Handle profile image upload and retrieval."""
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        try:
            
            if 'profile_pic' not in request.FILES:
                logger.error("No image file provided")
                return Response(
                    {"error": "No image file provided"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            image_file = request.FILES['profile_pic']
            
            # Basic validation
            if not image_file.content_type.startswith('image/'):
                logger.error(f"Invalid file type: {image_file.content_type}")
                return Response(
                    {"error": "Invalid file type. Please upload an image."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Size validation (e.g., 5MB limit)
            if image_file.size > 5 * 1024 * 1024:
                logger.error(f"File too large: {image_file.size} bytes")
                return Response(
                    {"error": "File size too large. Maximum size is 5MB."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = request.user

            # Create media directory if it doesn't exist
            try:
                media_root = os.path.join(settings.MEDIA_ROOT, 'profile_images')
                os.makedirs(media_root, exist_ok=True)
            except Exception as e:
                logger.error(f"Error creating media directory: {e}")
            
            # Update user's profile picture
            try:
                # Delete old profile picture file if it exists. Use FieldFile.path when available
                if user.profile_pic:
                    try:
                        # If the field has a filesystem path, remove that file
                        if hasattr(user.profile_pic, 'path') and user.profile_pic.path:
                            old_file_path = user.profile_pic.path
                            if os.path.exists(old_file_path):
                                os.remove(old_file_path)
                        else:
                            # Fallback: if it's stored as a string name, build the path
                            old_name = getattr(user.profile_pic, 'name', None) or str(user.profile_pic)
                            if old_name:
                                old_file_path = os.path.join(settings.MEDIA_ROOT, old_name)
                                if os.path.exists(old_file_path):
                                    os.remove(old_file_path)
                    except Exception as e:
                        logger.warning(f"Failed to delete old profile picture: {e}")

                # Generate a safe unique filename (use email + timestamp to reduce collisions)
                file_extension = os.path.splitext(image_file.name)[1]
                safe_email = user.email.replace('@', '_at_').replace('.', '_') if user.email else str(user.id)
                unique_filename = f"{safe_email}_{int(now().timestamp())}{file_extension}"
                file_path = os.path.join(settings.MEDIA_ROOT, 'profile_images', unique_filename)

                # Save the file manually to media folder
                with open(file_path, 'wb+') as destination:
                    for chunk in image_file.chunks():
                        destination.write(chunk)

                # Store the relative path (name) on the ImageField, not the MEDIA_URL
                relative_path = f"profile_images/{unique_filename}"
                user.profile_pic = relative_path
                user.save()

                # Construct the full profile picture URL using the field's url attribute
                try:
                    profile_pic_url = request.build_absolute_uri(user.profile_pic.url)
                except Exception:
                    # Fallback to building from MEDIA_URL
                    profile_pic_url = request.build_absolute_uri(f"{settings.MEDIA_URL}{relative_path}")

                return Response(
                    {
                        "message": "Profile picture updated successfully",
                        "profile_pic_url": profile_pic_url
                    },
                    status=status.HTTP_200_OK
                )

            except Exception as e:
                logger.error(f"Error saving profile picture: {e}", exc_info=True)
                return Response(
                    {"error": f"Error saving profile picture: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            logger.error(f"Error in profile image upload: {str(e)}", exc_info=True)
            return Response(
                {"error": f"An error occurred while uploading the profile picture: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class IBTradingAccountsView(APIView):
    """
    API endpoint to return all real trading accounts for the authenticated IB user.
    """
    authentication_classes = [BlacklistCheckingJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user or not user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        if not getattr(user, "IB_status", False):
            return Response({"error": "User is not an approved IB"}, status=status.HTTP_403_FORBIDDEN)
        # Get all real trading accounts for this IB
        accounts = TradingAccount.objects.filter(user=user, account_type__in=["standard", "basic", "pro"]).values("account_id")
        return Response(list(accounts), status=status.HTTP_200_OK)
