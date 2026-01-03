from django.views.static import serve as static_serve
from django.db.models import FloatField, F, Sum
from django.db.models.functions import ExtractMonth, ExtractYear
from django.utils import timezone
import os
import json
from datetime import datetime, timedelta
from urllib.parse import quote_plus

# Serve robots.txt and sitemap.xml from static directory
def robots_txt(request):
    static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
    return static_serve(request, path='robots.txt', document_root=static_dir)

def sitemap_xml(request):
    static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
    return static_serve(request, path='sitemap.xml', document_root=static_dir)
# --- IB Add Client Endpoint --- #
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
import random
from adminPanel.EmailSender import EmailSender
from adminPanel.serializers import UserInfoSerializer

class IBAddClientView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if not getattr(user, 'IB_status', False):
            return Response({"error": "You are not authorized to add clients."}, status=403)

        data = request.data
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        country = data.get('country', '').strip()

        if not name or not email:
            return Response({"error": "Name and email are required."}, status=400)

        # Split name into first and last
        parts = name.split()
        first_name = parts[0]
        last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''

        User = get_user_model()
        if User.objects.filter(email=email).exists():
            return Response({"error": "A user with this email already exists."}, status=400)

        # Generate a random username if needed
        username = email.split('@')[0] + str(random.randint(1000, 9999))

        # Generate a random password
        import string
        import secrets
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(10))

        # Create the client user with password
        client = User.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
            phone_number=phone,
            country=country,
            parent_ib=user,
            role='client',
            manager_admin_status='Client',
        )
        client.set_password(password)
        client.save()

        # Send welcome email with credentials
        try:
            EmailSender.send_new_user_from_admin(email, first_name, password)
        except Exception as e:
            # Log but do not fail the request if email fails
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send welcome email to {email}: {str(e)}")

        return Response({"success": True, "user_id": client.user_id}, status=201)
# Decimal is imported at module top; avoid importing inside function to prevent local variable shadowing
import time
import json
import base64
import requests
from django.utils import timezone
from datetime import datetime
import calendar

# Django Imports
from django.db import transaction as db_transaction
from django.db.models import Sum, Q
from django.utils.timezone import now
from django.shortcuts import get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.conf import settings

# Django REST Framework Imports
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.authentication import JWTAuthentication
import logging

logger = logging.getLogger(__name__)

# Project imports
from clientPanel.models import BankDetails
from clientPanel.serializers import BankDetailsSerializer, CryptoDetailsSerializer
from decimal import Decimal
from adminPanel.models import CryptoDetails

# Cryptography Imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Project-Specific Imports
from adminPanel.mt5.services import MT5ManagerActions
from adminPanel.models import Transaction, TradingAccount
from adminPanel.serializers import *
from adminPanel.views.views import get_client_ip

        
class LogoutView(APIView):
    """
    Secure logout endpoint that:
    1. Blacklists JWT refresh token (invalidates server-side)
    2. Explicitly deletes ALL auth-related cookies
    3. Returns clean response
    Accepts both GET and POST for flexibility
    """
    permission_classes = []  # Allow unauthenticated logout attempts
    
    def _perform_logout(self, request):
        """Common logout logic for both GET and POST"""
        try:
            # Try to get refresh token from multiple sources
            refresh_token = (
                request.data.get("refresh") if hasattr(request, 'data') else None
            ) or request.COOKIES.get('refresh_token')
            
            # Blacklist token if available (server-side invalidation)
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                except Exception as e:
                    # Token might be already blacklisted or invalid - continue with cookie deletion
                    pass
            
            # Create response
            resp = Response({
                "detail": "Successfully logged out.",
                "success": True
            }, status=status.HTTP_200_OK)
            
            # Use the same secure flag as when setting cookies
            secure_flag = not settings.DEBUG
            
            # CRITICAL: Must use set_cookie with max_age=0 and EXACT same parameters as when created
            # delete_cookie() doesn't work properly for HttpOnly cookies
            
            # HttpOnly auth cookies (JWT tokens) - MUST match login parameters exactly
            httponly_cookies = ['jwt_token', 'access_token', 'accessToken', 'refresh_token']
            for cookie_name in httponly_cookies:
                resp.set_cookie(
                    cookie_name, 
                    '', 
                    httponly=True, 
                    secure=secure_flag, 
                    samesite='Strict', 
                    path='/', 
                    max_age=0
                )
            
            # Non-HttpOnly cookies (user metadata)
            regular_cookies = ['user_role', 'user_name', 'user_email', 'user_id', 
                             'selectedAccountId', 'current_page']
            for cookie_name in regular_cookies:
                resp.set_cookie(
                    cookie_name, 
                    '', 
                    httponly=False, 
                    secure=secure_flag, 
                    samesite='Strict', 
                    path='/', 
                    max_age=0
                )
            
            # Django session cookies
            resp.set_cookie('sessionid', '', path='/', max_age=0)
            resp.set_cookie('csrftoken', '', path='/', max_age=0)
            
            return resp
            
        except Exception as e:
            # Even on error, return success and clear cookies
            resp = Response({
                "detail": "Logged out (with errors)",
                "success": True,
                "error": str(e)
            }, status=status.HTTP_200_OK)
            
            # Still delete cookies even if blacklisting failed
            secure_flag = not settings.DEBUG
            for cookie_name in ['jwt_token', 'access_token', 'accessToken', 'refresh_token']:
                resp.set_cookie(cookie_name, '', httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=0)
            for cookie_name in ['user_role', 'user_name', 'user_email', 'user_id']:
                resp.set_cookie(cookie_name, '', httponly=False, secure=secure_flag, samesite='Strict', path='/', max_age=0)
            
            return resp
    
    def post(self, request):
        """Handle POST logout requests"""
        return self._perform_logout(request)
    
    def get(self, request):
        """Handle GET logout requests"""
        return self._perform_logout(request)
        
class ValidateTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        This endpoint is used to validate the token.
        If the user is authenticated, it returns a success message.
        """
        # Return user info along with validation message if the user is authenticated
        user_info = {
            "username": request.user.username,
            "email": request.user.email,
        }
        return Response(
            {"message": "Token is valid", "user": user_info}, status=200
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_info_view(request):
    """
    This endpoint returns user info if the user is authenticated.
    If not, it returns a 401 Unauthorized response.
    """
    serializer = UserInfoSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

class RecentTransactionsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        transactions = Transaction.objects.filter(trading_account__user=user).order_by('-created_at')[:5]
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data)

class UserTradingAccountsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            accounts = TradingAccount.objects.filter(user=request.user, account_type='standard')
            mt5_warning = None
            
            try:
                # Import MT5ManagerActions only when needed to avoid import-time errors
                from adminPanel.mt5.services import MT5ManagerActions
                mt5action = MT5ManagerActions()
                for account in accounts:
                    account.balance = mt5action.get_balance(account.account_id)
                    account.save()
            except Exception as mt5_error:
                # Handle MT5 connection issues gracefully
                mt5_warning = f"MT5 server unavailable: {str(mt5_error)}"
                # Continue with existing account data from database
                
            # Fetch accounts again to get the updated data (or original data if MT5 failed)
            accounts = TradingAccount.objects.filter(user=request.user, account_type='standard')
            serializer = TradingAccountSerializer(accounts, many=True)
            
            response_data = {
                "accounts": serializer.data,
                "mt5_status": "connected" if mt5_warning is None else "disconnected",
                "warning": mt5_warning
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            # If we get here, it's likely a different error (not MT5 related)
            # Return the accounts with an error message
            try:
                accounts = TradingAccount.objects.filter(user=request.user, account_type='standard')
                serializer = TradingAccountSerializer(accounts, many=True)
                return Response({
                    "accounts": serializer.data,
                    "mt5_status": "disconnected",
                    "warning": f"Service error: {str(e)}"
                }, status=status.HTTP_200_OK)
            except Exception as final_error:
                return Response({"error": str(final_error)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserAccountsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            # Get standard trading accounts from database
            accounts = TradingAccount.objects.filter(user=request.user).exclude(account_type='prop')
            mt5_warning = None
            processed_accounts = []
            
            try:
                # Import MT5ManagerActions and process each account
                from adminPanel.mt5.services import MT5ManagerActions
                mt5action = MT5ManagerActions()
                
                for account in accounts:
                    # Verify account exists in MT5
                    try:
                        mt5_balance = mt5action.get_balance(account.account_id)
                        if mt5_balance is not False:  # Account exists in MT5
                            account.balance = mt5_balance
                            account.save()
                            processed_accounts.append(account)
                    except Exception as acc_error:
                        logger.warning(f"Failed to verify MT5 account {account.account_id}: {str(acc_error)}")
                        continue
                        
            except Exception as mt5_error:
                mt5_warning = f"MT5 server unavailable: {str(mt5_error)}"
                # Don't return any accounts if MT5 is unavailable
                processed_accounts = []
                
            # Only serialize accounts that have been verified in MT5
            serializer = TradingAccountSerializer(processed_accounts, many=True)
            
            response_data = {
                "accounts": serializer.data,
                "mt5_status": "connected" if not mt5_warning else "disconnected",
                "warning": mt5_warning
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error in UserAccountsView: {str(e)}")
            return Response({
                "error": str(e),
                "accounts": [],
                "mt5_status": "disconnected",
                "warning": "Service error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserDemoAccountsView(APIView):
    """
    Fetch all demo accounts belonging to the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        demo_accounts = DemoAccount.objects.filter(user=request.user)
        
        # Serialize accounts with user details
        accounts_data = []
        for account in demo_accounts:
            user = account.user
            accounts_data.append({
                'id': account.id,
                'account_id': account.account_id,
                'account_name': account.account_name,
                'holder_name': f"{user.first_name} {user.last_name}".strip() or user.email,
                'email': user.email,
                'phone': getattr(user, 'phone', ''),
                'leverage': account.leverage,
                'balance': float(account.balance),
                'created_at': account.created_at,
                'is_enabled': account.is_enabled,
                'is_algo_enabled': account.is_algo_enabled
            })
        
        return Response(accounts_data, status=status.HTTP_200_OK)

class UserTransactionHistoryView(APIView):
    """
    View to fetch the user's transaction history (non-pending transactions).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        # Include transactions where the user is the creator (Transaction.user)
        transactions = Transaction.objects.filter(
            Q(user=user) | Q(trading_account__user=user) | Q(from_account__user=user) | Q(to_account__user=user)
        ).exclude(status="pending").order_by("-created_at")
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data)

class PendingTransactionsView(APIView):
    """
    View to fetch the user's pending transactions.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        # Include transactions where the user created the transaction so investor-submitted
        # deposits (which target a manager trading_account) appear in their pending list.
        pending_transactions = Transaction.objects.filter(
            (Q(user=user) | Q(trading_account__user=user) | Q(from_account__user=user) | Q(to_account__user=user)),
            status="pending"
        ).order_by("-created_at")

        serializer = TransactionSerializer(pending_transactions, many=True)
        return Response(serializer.data)

class AvailablePackagesView(APIView):
    permission_classes = [IsAuthenticated]  

    def get(self, request):
        """
        Retrieve all available packages for authenticated users.
        """
        packages = Package.objects.all()  
        serializer = PackageSerializer(packages, many=True)
        return Response(serializer.data, status=200)


class IBStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        if not user.IB_status:
            return Response({"error": "You are not an IB user."}, status=403)

        commission_balance = user.total_earnings - user.total_commission_withdrawals
        
        # Get current month/year
        now = timezone.now()
        
        # Simple direct month/year filtering that matches verify script
        # Exclude demo account commissions
        current_month_query = CommissionTransaction.objects.filter(
            ib_user=user,
            created_at__month=now.month,
            created_at__year=now.year
        ).exclude(client_trading_account__account_type='demo')
        
        
        # Calculate total
        total_result = current_month_query.aggregate(
            total=Sum('commission_to_ib', output_field=FloatField())
        )
        

        
        # Get the final value with proper null handling
        raw_total = total_result['total']
        current_month_earnings = float(raw_total if raw_total is not None else 0)
        
        # Show sample transactions
        for t in current_month_query.order_by('-created_at')[:3]:
            print(f"{t.created_at}: ${t.commission_to_ib}")
        
        # (removed duplicate aggregation referencing undefined variable)
        
        # Manual verification
        manual_total = sum(float(t.commission_to_ib) for t in current_month_query.iterator())


        for t in current_month_query:
            print(f"Transaction at {t.created_at}: ${float(t.commission_to_ib)}")
        
        # Exclude demo account commissions from all earnings calculations
        earnings_per_month = CommissionTransaction.objects.filter(ib_user=user).exclude(
            client_trading_account__account_type='demo'
        ).values(
            'created_at__year', 'created_at__month'
        ).annotate(total=Sum('commission_to_ib')).order_by('created_at__year', 'created_at__month')

        earnings_per_year = CommissionTransaction.objects.filter(ib_user=user).exclude(
            client_trading_account__account_type='demo'
        ).values(
            'created_at__year'
        ).annotate(total=Sum('commission_to_ib')).order_by('created_at__year')

        earnings_per_level = CommissionTransaction.objects.filter(ib_user=user).exclude(
            client_trading_account__account_type='demo'
        ).values(
            'ib_level'
        ).annotate(total=Sum('commission_to_ib')).order_by('ib_level')

        # Earnings per client - exclude demo account commissions
        earnings_per_client = CommissionTransaction.objects.filter(ib_user=user).exclude(
            client_trading_account__account_type='demo'
        ).values(
            'client_user__email'
        ).annotate(total=Sum('commission_to_ib')).order_by('-total')

        from adminPanel.models import CustomUser
        # If a search query is provided, perform a server-side search and return matching clients
        q = request.query_params.get('q')
        if q:
            try:
                all_clients = request.user.get_all_clients() if hasattr(request.user, 'get_all_clients') else []
            except Exception:
                all_clients = []

            qlc = q.strip().lower()
            results = []

            def get_parent_chain(uobj):
                chain = []
                cur = getattr(uobj, 'parent_ib', None)
                while cur:
                    cid = getattr(cur, 'user_id', None) or getattr(cur, 'id', None)
                    chain.append(str(cid))
                    cur = getattr(cur, 'parent_ib', None)
                return chain

            for c in all_clients:
                try:
                    name = f"{getattr(c, 'first_name', '')} {getattr(c, 'last_name', '')}".strip()
                    email = getattr(c, 'email', '') or ''
                    phone = getattr(c, 'phone_number', '') or ''
                    if qlc in name.lower() or qlc in email.lower() or qlc in phone.lower():
                        cid = getattr(c, 'user_id', None) or getattr(c, 'id', None)
                        results.append({
                            'id': str(cid),
                            'name': name,
                            'email': email,
                            'phone': phone,
                            'registered_date': getattr(c, 'date_joined', None).strftime('%Y-%m-%d') if getattr(c, 'date_joined', None) else '',
                            'parent_chain': get_parent_chain(c)
                        })
                except Exception:
                    continue

            return Response({'matches': results[:200]})
        direct_clients_count = CustomUser.objects.filter(parent_ib=user).count()
        stats = {
            "total_clients": len(user.get_all_clients()),
            "direct_clients": direct_clients_count,
            "total_earnings": round(float(user.total_earnings),2),
            "total_commission_withdrawals": float(user.total_commission_withdrawals),
            "commission_balance": float(commission_balance),
            "joined_date": user.date_joined,
            "ib_signup_link": f"/referralsignup?referral={user.user_id}",
            "current_month_earnings": float(current_month_earnings or 0),  # Ensure we convert None to 0
            "earnings_per_month": list(earnings_per_month),
            "earnings_per_year": list(earnings_per_year),
            "earnings_per_level": list(earnings_per_level),
            "earnings_per_client": list(earnings_per_client),
        }

        return Response(stats)

class IBClientTreeView(APIView):
    permission_classes = [IsAuthenticated]

    def get_client_tree(self, ib_user, level=1, max_level=None, load_children=True):
        """
        Recursively fetch the client tree up to max_level.
        load_children: if False, don't load child nodes but still indicate if children exist
        """
        # Protect against cycles in the IB graph by tracking visited user IDs.
        # Use a local visited set passed through recursive calls.
        return self._get_client_tree_safe(ib_user, level=level, max_level=max_level, visited=None, load_children=load_children)

    def _get_client_tree_safe(self, ib_user, level=1, max_level=None, visited=None, load_children=True):
        """Helper that carries a visited set to avoid infinite recursion.
        load_children: if False, don't load child nodes but still indicate if children exist
        """
        if visited is None:
            visited = set()

        # If we've already visited this user, there's a cycle — stop here.
        user_id = getattr(ib_user, 'user_id', None) or getattr(ib_user, 'id', None)
        if user_id in visited:
            return None

        # Mark current user as visited for the current branch
        visited.add(user_id)

        # Enforce max depth
        if max_level is not None and level > max_level:
            return None

        # Safely get children (related_name 'clients' expected); fall back to empty queryset
        try:
            children = ib_user.clients.all()
        except Exception:
            children = []

        clients_list = []
        if load_children:
            for child in children:
                # Pass a copy so sibling branches don't inherit visited nodes from each other
                sub_tree = self._get_client_tree_safe(child, level + 1, max_level, visited.copy(), load_children)
                if sub_tree:
                    clients_list.append(sub_tree)
        
        # Determine if this node has children that are within max_level
        # Check if there are actual children AND if next level is within max_level
        actual_has_children = len(children) > 0
        children_within_limit = True
        if max_level is not None and (level + 1) > max_level:
            children_within_limit = False

        return {
            "id": user_id,
            "name": f"{getattr(ib_user, 'first_name', '')} {getattr(ib_user, 'last_name', '')}".strip(),
            "email": getattr(ib_user, 'email', ''),
            "phone": getattr(ib_user, 'phone_number', ''),
            "registered_date": ib_user.date_joined.strftime('%Y-%m-%d') if hasattr(ib_user, 'date_joined') else '',
            "country": getattr(ib_user, 'country', ''),
            "level": level,
            "clients": clients_list,
            "has_children": actual_has_children and children_within_limit,  # Only true if children exist AND within level limit
            # Account stats will be populated later via bulk loading
            "accounts": [],
        }

    def _collect_account_stats(self, user_obj, ib_user=None):
        """Wrapper for backward compatibility - calls optimized version with single user"""
        result = self._collect_account_stats_optimized([user_obj], ib_user)
        user_id = getattr(user_obj, 'id', getattr(user_obj, 'user_id', None))
        return result.get(user_id, [])

    def _collect_account_stats_optimized(self, user_objs, ib_user=None):
        """Optimized version that bulk-loads data for multiple users to avoid N+1 queries.

        Args:
            user_objs: List of user objects or queryset
            ib_user: The IB user requesting the data

        Returns:
            Dict mapping user_id to list of account summaries
        """
        from adminPanel.models import TradingAccount, Transaction, CommissionTransaction, TradeGroup
        from django.db.models import Sum, Q
        from django.db.models import Prefetch

        # Convert to list if queryset
        if hasattr(user_objs, 'values_list'):
            user_ids = list(user_objs.values_list('id', flat=True))
        else:
            user_ids = [getattr(u, 'id', getattr(u, 'user_id', None)) for u in user_objs]

        result = {user_id: [] for user_id in user_ids}

        if not user_ids:
            return result

        try:
            # Bulk load all trading accounts for these users
            accounts = TradingAccount.objects.filter(user_id__in=user_ids).select_related('user')

            # Create account lookup by user_id
            accounts_by_user = {}
            all_account_ids = []
            for acct in accounts:
                user_id = acct.user_id
                if user_id not in accounts_by_user:
                    accounts_by_user[user_id] = []
                accounts_by_user[user_id].append(acct)
                all_account_ids.append(acct.account_id)

            # Bulk load all transactions for these accounts
            transactions = Transaction.objects.filter(
                trading_account_id__in=all_account_ids,
                transaction_type__in=['deposit_trading', 'withdraw_trading'],
                status='approved'
            ).values('trading_account', 'transaction_type').annotate(total=Sum('amount'))

            # Create transaction lookup
            deposits_by_account = {}
            withdrawals_by_account = {}
            for tx in transactions:
                acct_id = tx['trading_account']
                amount = tx['total'] or 0
                if tx['transaction_type'] == 'deposit_trading':
                    deposits_by_account[acct_id] = amount
                elif tx['transaction_type'] == 'withdraw_trading':
                    withdrawals_by_account[acct_id] = amount

            # Bulk load commission transactions
            commission_filter = {'client_trading_account_id__in': all_account_ids}
            if ib_user:
                commission_filter['ib_user'] = ib_user

            commission_data = CommissionTransaction.objects.filter(
                **commission_filter
            ).values('client_trading_account', 'client_user').annotate(
                total_lots=Sum('lot_size'),
                total_commission=Sum('commission_to_ib')
            )

            # Create commission lookup
            lots_by_account_user = {}
            commission_by_account_user = {}
            for comm in commission_data:
                key = (comm['client_trading_account'], comm['client_user'])
                lots_by_account_user[key] = comm['total_lots'] or 0
                commission_by_account_user[key] = comm['total_commission'] or 0

            # Bulk load TradeGroups for caching
            all_group_names = set()
            for acct in accounts:
                if getattr(acct, 'group_name', None):
                    all_group_names.add(acct.group_name)

            # Create TradeGroup cache
            trade_groups = TradeGroup.objects.filter(
                Q(name__in=all_group_names) | Q(group_id__in=all_group_names)
            )
            tg_cache = {}
            for tg in trade_groups:
                tg_cache[tg.name.lower()] = tg
                tg_cache[tg.group_id.lower()] = tg

            def resolve_tradegroup_cached(group_name):
                """Cached version of TradeGroup resolution"""
                if not group_name:
                    return None
                key = group_name.lower()
                if key in tg_cache:
                    return tg_cache[key]

                # Try unescaping
                try:
                    unescaped = group_name.replace('\\\\', '\\')
                    if unescaped != group_name:
                        key2 = unescaped.lower()
                        if key2 in tg_cache:
                            return tg_cache[key2]
                except:
                    pass

                # Try icontains match
                for tg in trade_groups:
                    if group_name.lower() in tg.name.lower() or group_name.lower() in tg.group_id.lower():
                        tg_cache[key] = tg
                        return tg

                return None

            def extract_clean_group_name(group_name):
                """Extract clean name from MT5 group path like 'demo\\KRSNA' -> 'KRSNA' """
                if not group_name:
                    return ''
                parts = group_name.replace('/', '\\').split('\\')
                for part in reversed(parts):
                    if part and not part.lower() in ['demo', 'real']:
                        return part
                return parts[-1] if parts and parts[-1] else group_name

            # Process each user's accounts
            for user_id, user_accounts in accounts_by_user.items():
                account_summaries = []

                for acct in user_accounts:
                    # Get transaction data
                    deposits = deposits_by_account.get(acct.id, 0)
                    withdrawals = withdrawals_by_account.get(acct.id, 0)

                    # Get commission data
                    comm_key = (acct.id, user_id)
                    total_lots = lots_by_account_user.get(comm_key, 0)
                    total_commission = commission_by_account_user.get(comm_key, 0)

                    # Resolve TradeGroup
                    group_alias = ''
                    group_identifier = ''
                    if getattr(acct, 'group_name', None):
                        group_identifier = acct.group_name
                        tg = resolve_tradegroup_cached(acct.group_name)
                        if tg:
                            group_alias = tg.alias or extract_clean_group_name(tg.name)
                            group_identifier = tg.group_id or tg.name or group_identifier
                        else:
                            group_alias = extract_clean_group_name(acct.group_name)

                    account_summaries.append({
                        'account_id': acct.account_id,
                        'account_type': acct.account_type,
                        'balance': float(acct.balance or 0),
                        'total_lots': float(total_lots),
                        'total_deposits': float(deposits),
                        'total_withdrawals': float(withdrawals),
                        'total_commission': float(total_commission),
                        'group_name': acct.group_name or '',
                        'group_alias': group_alias,
                        'group_id': group_identifier,
                    })

                result[user_id] = account_summaries

        except Exception as e:
            # Fallback to empty results on error
            print(f"Error in optimized account stats: {e}")

        return result

    def get(self, request):
        user = request.user
        
        # Store request user for use in helper methods
        self.request_user = user

        if not user.IB_status:
            return Response({"error": "You are not authorized to view the client tree."}, status=403)

        from adminPanel.models import CustomUser
        
        # Get the IB's commission profile to determine max levels
        commission_profile = user.commissioning_profile
        profile_max_levels = None
        profile_info = None
        
        if commission_profile:
            try:
                profile_max_levels = commission_profile.get_max_levels()
                
                # Build profile info for display
                if commission_profile.use_percentage_based or commission_profile.dynamic_levels:
                    if commission_profile.dynamic_levels:
                        # Dynamic levels (new system)
                        sorted_levels = sorted(commission_profile.dynamic_levels, key=lambda x: x.get('level', 0))
                        levels_display = ', '.join([
                            f"L{lc.get('level')}: {lc.get('percentage', 0)}%" 
                            for lc in sorted_levels if 'percentage' in lc
                        ])
                    else:
                        # Legacy percentage-based
                        percentages = commission_profile.get_level_percentages_list()
                        levels_display = ', '.join([f"L{i+1}: {p}%" for i, p in enumerate(percentages)])
                else:
                    # USD per lot
                    if commission_profile.dynamic_levels:
                        # Dynamic levels (new system)
                        sorted_levels = sorted(commission_profile.dynamic_levels, key=lambda x: x.get('level', 0))
                        levels_display = ', '.join([
                            f"L{lc.get('level')}: ${lc.get('usd_per_lot', 0)}/lot" 
                            for lc in sorted_levels if 'usd_per_lot' in lc
                        ])
                    else:
                        # Legacy USD per lot
                        amounts = commission_profile.get_level_amounts_list()
                        levels_display = ', '.join([f"L{i+1}: ${a}/lot" for i, a in enumerate(amounts)])
                
                profile_info = {
                    'name': commission_profile.name,
                    'max_levels': profile_max_levels,
                    'levels_display': levels_display,
                    'use_percentage_based': commission_profile.use_percentage_based
                }
            except Exception as e:
                print(f"Error getting commission profile info: {e}")
                profile_max_levels = None
        
        # Handle search queries
        q = request.query_params.get('q', '').strip()
        if q:
            # Get all clients under this IB and search them
            all_clients = []
            try:
                direct_clients = CustomUser.objects.filter(parent_ib=user)
                def collect_children(clients, visited=None):
                    if visited is None:
                        visited = set()
                    for c in clients:
                        cid = getattr(c, 'user_id', None) or getattr(c, 'id', None)
                        if cid not in visited:
                            visited.add(cid)
                            all_clients.append(c)
                            # Recursively collect their clients if they're an IB
                            if getattr(c, 'IB_status', False):
                                collect_children(c.clients.all(), visited)
                collect_children(direct_clients)
            except Exception as e:
                print(f"Error collecting clients: {e}")
                all_clients = []

            # Search across collected clients
            matches = []
            qlc = q.lower()
            for c in all_clients:
                try:
                    name = f"{getattr(c, 'first_name', '')} {getattr(c, 'last_name', '')}".strip()
                    email = getattr(c, 'email', '') or ''
                    phone = getattr(c, 'phone_number', '') or ''
                    if qlc in name.lower() or qlc in email.lower() or qlc in phone.lower():
                        cid = getattr(c, 'user_id', None) or getattr(c, 'id', None)
                        # collect parent chain for this match
                        parent_chain = []
                        cur = getattr(c, 'parent_ib', None)
                        while cur:
                            pid = getattr(cur, 'user_id', None) or getattr(cur, 'id', None)
                            if pid:
                                parent_chain.append(str(pid))
                            cur = getattr(cur, 'parent_ib', None)
                        # Get account summaries for this client (same as normal tree display)
                        client_accounts = self._collect_account_stats(c, user)
                        
                        matches.append({
                            'id': str(cid),
                            'name': name,
                            'email': email,
                            'phone': phone,
                            'registered_date': getattr(c, 'date_joined', None).strftime('%Y-%m-%d') if getattr(c, 'date_joined', None) else '',
                            'parent_chain': parent_chain,
                            'level': len(parent_chain) + 1,
                            'accounts': client_accounts,  # Add accounts to search results
                            'clients': [],  # No children loaded for search results
                            'has_children': getattr(c, 'IB_status', False) and CustomUser.objects.filter(parent_ib=c).exists()  # Indicate if this client has children
                        })
                except Exception as e:
                    print(f"Error processing client {getattr(c, 'email', '<unknown>')}: {e}")
                    continue

            # Handle pagination
            page = int(request.query_params.get('page', 1))
            per_page = int(request.query_params.get('per_page', 50))
            total_matches = len(matches)
            
            # Calculate pagination bounds
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_matches = matches[start_idx:end_idx]
            
            # Return paginated matches with metadata
            return Response({
                'clients': paginated_matches,
                'max_levels': None,
                'level_percentages': None,
                'is_search_result': True,
                'pagination': {
                    'total': total_matches,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total_matches + per_page - 1) // per_page,
                    'has_next': end_idx < total_matches,
                    'has_previous': page > 1
                }
            })
        else:
            # Check if this is a lazy-load request for a specific parent's children
            parent_id = request.query_params.get('parent_id')
            
            if parent_id:
                # Lazy-load children of a specific parent
                try:
                    parent_user = CustomUser.objects.get(user_id=parent_id)
                    
                    # Verify the parent is in this IB's hierarchy
                    # Check if parent is the IB themselves or a descendant
                    is_authorized = False
                    if parent_user.id == user.id:
                        is_authorized = True
                    else:
                        # Check if parent_user is under this IB
                        temp = parent_user
                        while temp.parent_ib:
                            if temp.parent_ib.id == user.id:
                                is_authorized = True
                                break
                            temp = temp.parent_ib
                    
                    if not is_authorized:
                        return Response({"error": "Unauthorized parent access"}, status=403)
                    
                    # Calculate parent's level to determine children's level
                    parent_level = 0
                    temp = parent_user
                    while temp.parent_ib and temp.parent_ib.id != user.id:
                        parent_level += 1
                        temp = temp.parent_ib
                    
                    children_level = parent_level + 1
                    
                    # Check if children_level exceeds max_level from profile
                    max_level = profile_max_levels
                    if max_level and children_level > max_level:
                        # Children exceed max level, return empty
                        return Response({
                            'clients': [],
                            'max_levels': max_level,
                            'profile_info': profile_info,
                            'message': f'Children at level {children_level} exceed maximum profile level {max_level}'
                        })
                    
                    # Fetch immediate children
                    children = CustomUser.objects.filter(parent_ib=parent_user)
                    
                    # Handle pagination
                    page = int(request.query_params.get('page', 1))
                    per_page = int(request.query_params.get('per_page', 20))
                    
                    # Paginate children
                    from django.core.paginator import Paginator
                    paginator = Paginator(list(children), per_page)
                    page_obj = paginator.get_page(page)
                    
                    # Build children data with max_level constraint
                    children_data = []
                    
                    # Bulk load account stats for all children in this page
                    if page_obj:
                        bulk_account_stats = self._collect_account_stats_optimized(page_obj, user)
                    
                    for child in page_obj:
                        child_data = self.get_client_tree(child, level=children_level, max_level=max_level)
                        if child_data:
                            # Use pre-loaded account stats
                            child_id = getattr(child, 'id', getattr(child, 'user_id', None))
                            child_data["accounts"] = bulk_account_stats.get(child_id, [])
                            children_data.append(child_data)
                    
                    return Response({
                        'clients': children_data,
                        'max_levels': max_level,
                        'profile_info': profile_info,
                        'pagination': {
                            'total': paginator.count,
                            'page': page,
                            'per_page': per_page,
                            'total_pages': paginator.num_pages,
                            'has_next': page_obj.has_next(),
                            'has_previous': page_obj.has_previous()
                        }
                    })
                    
                except CustomUser.DoesNotExist:
                    return Response({"error": "Parent not found"}, status=404)
                except Exception as e:
                    print(f"Error loading children for parent {parent_id}: {e}")
                    return Response({"error": "Failed to load children"}, status=500)
            
            # Normal tree view without search
            # Use commission profile's max_level by default, but allow override via query param
            max_level = request.query_params.get('max_level')
            level_percentages = request.query_params.get('level_percentages')  # e.g., "50,20,20,10"
            
            # If level_percentages provided, calculate max_level from it
            if level_percentages and max_level is None:
                try:
                    percentages = [p.strip() for p in level_percentages.split(',') if p.strip()]
                    max_level = len(percentages)
                except:
                    max_level = None
            
            # If no max_level specified and no level_percentages, use profile's max_level
            if max_level is None and profile_max_levels:
                max_level = profile_max_levels
            
            try:
                max_level = int(max_level) if max_level is not None else None
            except ValueError:
                max_level = None
            
            # Get pagination parameters
            page = int(request.query_params.get('page', 1))
            per_page = int(request.query_params.get('per_page', 20))
                
            # Get direct clients (all clients, not just IBs) and paginate them
            direct_clients = CustomUser.objects.filter(parent_ib=user).order_by('-date_joined')
            
            # Apply pagination
            from django.core.paginator import Paginator
            paginator = Paginator(direct_clients, per_page)
            page_obj = paginator.get_page(page)
            
            # Build tree for paginated clients only (lazy load - no children initially)
            clients_data = []
            
            # Bulk load account stats for all clients in this page for better performance
            if page_obj:
                bulk_account_stats = self._collect_account_stats_optimized(page_obj, user)
            
            for client in page_obj:
                tree_node = self.get_client_tree(client, level=1, max_level=max_level, load_children=False)
                if tree_node:
                    # Use pre-loaded account stats instead of loading individually
                    client_id = getattr(client, 'id', getattr(client, 'user_id', None))
                    tree_node["accounts"] = bulk_account_stats.get(client_id, [])
                    clients_data.append(tree_node)
            
            response_data = {
                "clients": clients_data,
                "max_levels": max_level,
                "level_percentages": level_percentages,
                "pagination": {
                    "total": paginator.count,
                    "page": page,
                    "per_page": per_page,
                    "total_pages": paginator.num_pages,
                    "has_next": page_obj.has_next(),
                    "has_previous": page_obj.has_previous()
                }
            }
            
            # Include profile info if available
            if profile_info:
                response_data['profile_info'] = profile_info
            
            return Response(response_data)


class IBCommissionTransactionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        
        if not user.IB_status:
            return Response({"error": "You are not authorized to view commission transactions."}, status=403)

        
        transactions = CommissionTransaction.objects.filter(ib_user=user)
        serializer = CommissionTransactionSerializer(transactions, many=True)
        return Response(serializer.data)

class CommissionBalanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.IB_status:
            return Response({"error": "Unauthorized"}, status=403)

        balance = user.total_earnings - user.total_commission_withdrawals
        return Response({"withdrawable_balance": float(balance)})

class RequestWithdrawalView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        amount = request.data.get("amount")
        account_id = request.data.get("account_id") 
        comment = request.data.get("comment", "")

        if not amount:
            return Response({"error": "Invalid amount"}, status=400)
        if float(amount) <= 0:
            return Response({"error": "Invalid amount"}, status=400)
        if Decimal(str(amount)) > Decimal(str(user.total_earnings)) - Decimal(str(user.total_commission_withdrawals)):
            return Response({"error": "Greater amount "+str(round(float(amount),2)) + " "+str(user.total_earnings)+" "+str(user.total_commission_withdrawals)}, status=400)
        
        amount = round(float(amount), 2)
        try:
            account = TradingAccount.objects.get(account_id=account_id, user=user)
        except TradingAccount.DoesNotExist:
            return Response({"error": "Invalid trading account selection" }, status=400)

        transaction = Transaction.objects.create(
            user=user,
            transaction_type="commission_withdrawal",
            amount=amount,
            status="pending",
            trading_account=account,
            migrated_to_old_withdrawal=False,
        )

        ActivityLog.objects.create(
            user=user,
            activity=f"Requested commission withdrawal of {amount} to account {account_id} with comment: '{comment}'",
            ip_address=get_client_ip(request),
            endpoint=request.path,
            activity_type="create",
            activity_category="client",
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            timestamp=now(),
            related_object_id=transaction.id,
            related_object_type="Transaction",
        )

        return Response({"success": "Withdrawal request submitted."})
    
class CommissionTransactionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        
        transactions = Transaction.objects.filter(
            user=user, transaction_type="commission_withdrawal"
        )
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data)

class ManualDepositView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Debug: log incoming request metadata to help diagnose unexpected redirects (302)
            try:
                logger = logging.getLogger(__name__)
                proto = request.META.get('wsgi.url_scheme') or request.META.get('HTTP_X_FORWARDED_PROTO') or ''
                logger.info(f"CheezePay notify incoming request: method={request.method} path={request.get_full_path()} remote={request.META.get('REMOTE_ADDR')} host={request.META.get('HTTP_HOST')} proto={proto} content_type={request.META.get('CONTENT_TYPE')}")
                body_len = len(request.body) if hasattr(request, 'body') and request.body is not None else 0
                logger.debug(f"CheezePay notify body length: {body_len}")
            except Exception:
                pass
            
            mam_id = request.data.get("mam_id")
            amount = request.data.get("amount")
            proof = request.FILES.get("proof")

            
            if not mam_id or not amount or not proof:
                return Response(
                    {"error": "All fields (mam_id, amount, proof) are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                # Try resolving mam_id as a PAMAccount first (by PAM id or by MT5 login).
                # This allows manual deposits to target a PAMM manager account even
                # when the frontend doesn't include role=investor.
                pamm = None
                try:
                    from clientPanel.models import PAMAccount
                except Exception:
                    PAMAccount = None

                if PAMAccount is not None:
                    # Try by PAMAccount primary key first (safe for integer/string ids)
                    try:
                        pamm = PAMAccount.objects.filter(id=mam_id).first()
                    except Exception:
                        pamm = None

                    # If not found by PAM id, try matching MT5 login
                    if not pamm:
                        try:
                            pamm = PAMAccount.objects.filter(mt5_login=str(mam_id)).first()
                        except Exception:
                            pamm = None

                if pamm:
                    # Found a PAMAccount -> use the manager's trading account (no ownership required)
                    manager_account = TradingAccount.objects.filter(account_id=str(pamm.mt5_login)).first()
                    if not manager_account:
                        # If no TradingAccount exists for the manager yet, create a minimal record
                        try:
                            # Determine profit sharing percentage for the MAM account
                            ps_value = getattr(pamm, 'profit_share', None)
                            try:
                                ps_decimal = Decimal(str(ps_value)) if ps_value is not None else None
                            except Exception:
                                ps_decimal = None

                            # If missing or zero, default to 1.00% to satisfy model validation
                            if not ps_decimal or ps_decimal == Decimal('0'):
                                ps_decimal = Decimal('1.00')
                                logger.warning(f"PAM {pamm.id} has no profit_share set; defaulting TradingAccount.profit_sharing_percentage to 1.00%")

                            manager_account = TradingAccount.objects.create(
                                user=pamm.manager,
                                account_id=str(pamm.mt5_login),
                                account_type='mam',
                                account_name=(pamm.name or f"PAMM {pamm.id}"),
                                leverage=getattr(pamm, 'leverage', 100),
                                balance=Decimal('0.00'),
                                equity=Decimal('0.00'),
                                margin=Decimal('0.00'),
                                margin_free=Decimal('0.00'),
                                margin_level=Decimal('0.00'),
                                # Ensure required MAM fields are populated to satisfy model validation
                                profit_sharing_percentage=ps_decimal,
                                status='active',
                                is_enabled=True,
                                is_trading_enabled=True,
                            )
                        except Exception as e:
                            logger.error(f"Failed to auto-create TradingAccount for PAM {pamm.id}: {e}")
                            raise TradingAccount.DoesNotExist()
                    account = manager_account
                else:
                    # No PAM found: fall back to strict ownership lookup (legacy behaviour)
                    account = TradingAccount.objects.get(account_id=str(mam_id), user=request.user)
            except TradingAccount.DoesNotExist:
                # If the account exists but belongs to another user, return 403 to indicate ownership issue
                if TradingAccount.objects.filter(account_id=str(mam_id)).exists():
                    return Response(
                        {"error": "Trading account not owned by current user."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
                return Response(
                    {"error": "Trading account not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            
            transaction = Transaction.objects.create(
                user=request.user,
                trading_account=account,
                transaction_type="deposit_trading",
                amount=Decimal(amount),
                status="pending",
                description="Manual deposit request",
                migrated_to_old_withdrawal=False,
            )

            if proof:
                transaction.document = proof
                transaction.save()

            # If this deposit targets a PAM manager and the requester is an investor,
            # create or update a PAMInvestment record so the investor's allocation is tracked.
            try:
                # Import locally to avoid circular import issues at module import time
                from clientPanel.models import PAMInvestment
                # Only create investment if the target PAM exists and requester is not the manager
                if pamm and request.user != pamm.manager:
                    try:
                        invest_amount = Decimal(amount)
                    except Exception:
                        invest_amount = Decimal('0.00')

                    investment = PAMInvestment.objects.filter(investor=request.user, pam_account=pamm).first()
                    if investment:
                        investment.amount = investment.amount + invest_amount
                        investment.save()
                        ActivityLog.objects.create(
                            user=request.user,
                            activity=f"Increased investment in PAM {pamm.id} by {invest_amount} (new total: {investment.amount})",
                            ip_address=get_client_ip(request),
                            endpoint=request.path,
                            activity_type="update",
                            activity_category="client",
                            user_agent=request.META.get("HTTP_USER_AGENT", ""),
                            timestamp=now(),
                            related_object_id=investment.id,
                            related_object_type="PAMInvestment",
                        )
                    else:
                        investment = PAMInvestment.objects.create(
                            investor=request.user,
                            pam_account=pamm,
                            amount=invest_amount,
                        )
                        ActivityLog.objects.create(
                            user=request.user,
                            activity=f"Created investment in PAM {pamm.id} of {invest_amount}",
                            ip_address=get_client_ip(request),
                            endpoint=request.path,
                            activity_type="create",
                            activity_category="client",
                            user_agent=request.META.get("HTTP_USER_AGENT", ""),
                            timestamp=now(),
                            related_object_id=investment.id,
                            related_object_type="PAMInvestment",
                        )
            except Exception:
                # Don't block deposit creation if investment logging fails; just log
                logger.exception("Failed to create/update PAMInvestment after manual deposit")
            
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Created manual deposit request of {amount} for account {mam_id}.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=transaction.id,
                related_object_type="Transaction",
            )

            
            return Response(
                {"message": "Manual deposit request created successfully."},
                status=status.HTTP_201_CREATED,
            )

        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Trading account not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        

# ✅ CheesePay Initiate View
@method_decorator(csrf_exempt, name='dispatch')
class CheesePayInitiateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, FormParser]  # Support both JSON and form data
    # Uses default authentication from settings: BlacklistCheckingJWTAuthentication which checks both headers and cookies

    def post(self, request, *args, **kwargs):
        try:
            
            # Support both mam_id (legacy) and account_id parameters
            account_id = request.data.get("account_id") or request.data.get("mam_id")
            amount = request.data.get("amount_usd")
            amount_inr = request.data.get("amount_inr")
            
           
            if not account_id or not amount:
                return Response(
                    {"success": False, "error": "All fields (account_id or mam_id, amount_usd) are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            account = get_object_or_404(TradingAccount, account_id=account_id, user=request.user)
           
            # Create transaction entry
            transaction = Transaction.objects.create(
                user=request.user,
                trading_account=account,
                transaction_type="deposit_trading",
                amount=Decimal(amount),
                status="pending",
                source="CheesePay",
                migrated_to_old_withdrawal=False,
            )

            # Get user data from request (sent by frontend) or fallback to user model
            user_name = request.data.get("user_name") or f"{request.user.first_name or ''} {request.user.last_name or ''}".strip() or "Unknown"
            user_email = request.data.get("email") or getattr(request.user, 'email', None) or "unknown@example.com"
            user_phone = request.data.get("phone") or getattr(request.user, 'phone_number', None) or getattr(request.user, 'phone', None) or "0000000000"

            # Try different amount formats to see what CheesePay expects
            try:
                # Keep original rupees amount as decimal with 2 places
                amount_inr_decimal = round(float(amount_inr), 2)
                
                # Use paise format (integer) like the working server
                final_amount = amount_inr_decimal
                
            except (ValueError, TypeError) as e:
                return Response(
                    {"success": False, "error": f"Invalid INR amount provided: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Validate user data
            if not user_name or len(user_name.strip()) == 0:
                user_name = "Unknown User"
            if not user_email or '@' not in user_email:
                user_email = "unknown@example.com"
            if not user_phone or len(user_phone) < 10:
                user_phone = "0000000000"


            pay_in_response = pay_in(
                amount=final_amount,  
                phone=user_phone,
                name=user_name,
                email=user_email,
                transactionid=transaction.id
            )

            # Check if pay_in returned None (indicates an error occurred)
            if pay_in_response is None:
                transaction.status = "failed"
                transaction.save()
                return Response(
                    {
                        "success": False,
                        "error": "Failed to initialize CheesePay payment. Please check your credentials or try again later.",
                        "details": "CheesePay API returned an error response. Please contact support if this persists."
                    },
                    status=status.HTTP_502_BAD_GATEWAY,
                )

            # Ensure we have a structured response (dict) from pay_in; otherwise return diagnostics
            if isinstance(pay_in_response, dict) and pay_in_response:
                # Robust extraction: check common keys at top-level first, then inside a nested 'data' dict
                payment_url = None
                candidate_keys = ("cashierLink", "cashier_link", "paymentUrl", "payment_url", "url")

                for k in candidate_keys:
                    v = pay_in_response.get(k)
                    if v:
                        payment_url = v
                        break

                # If not found, check nested 'data' field
                if not payment_url:
                    nested = pay_in_response.get("data")
                    if isinstance(nested, dict):
                        for k in candidate_keys:
                            v = nested.get(k)
                            if v:
                                payment_url = v
                                break
                    elif isinstance(nested, str) and nested.startswith("http"):
                        # Some APIs return the URL directly as a string inside 'data'
                        payment_url = nested

                if payment_url:
                    return Response(
                        {
                            "success": True,
                            "message": "CheezePay deposit request created successfully.",
                            "payment_url": payment_url,
                            "transaction_id": transaction.id,
                        },
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    # Return 502 Bad Gateway with diagnostic payload to help support triage
                    return Response(
                        {
                            "success": False,
                            "error": "Failed to generate CheezePay payment URL - no URL in response.",
                            "diagnostic": pay_in_response,
                        },
                        status=status.HTTP_502_BAD_GATEWAY,
                    )
            else:
                return Response(
                    {
                        "success": False,
                        "error": "Failed to generate CheezePay payment request.",
                        "diagnostic": pay_in_response,
                    },
                    status=status.HTTP_502_BAD_GATEWAY,
                )

        except TradingAccount.DoesNotExist:
            return Response(
                {"success": False, "error": "Trading account not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"success": False, "error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
            
            
class USDTDepositView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  

    def post(self, request, *args, **kwargs):
        try:
            mam_id = request.data.get("mam_id")
            amount = request.data.get("amount")
            proof = request.FILES.get("proof")

            
            if not mam_id or not amount or not proof:
                return Response(
                    {"error": "All fields (mam_id, amount, proof) are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            
            try:
                account = TradingAccount.objects.get(account_id=mam_id, user=request.user)
            except TradingAccount.DoesNotExist:
                return Response(
                    {"error": "Trading account not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            
            transaction = Transaction.objects.create(
                user=request.user,
                trading_account=account,
                transaction_type="deposit_trading",  
                amount=Decimal(amount),
                status="pending",
                description="USDT Deposit request.",
                document=proof,
                migrated_to_old_withdrawal=False,
            )
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Created USDT deposit request of {amount} for account {mam_id}.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=transaction.id,
                related_object_type="Transaction",
            )
            
            serializer = TransactionSerializer(transaction)
            return Response(
                {"message": "USDT deposit request created successfully.", "transaction": serializer.data},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class WithdrawInfoView(APIView):
    """
    Provides information about withdrawable balance and available withdrawal methods.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, mam_id, *args, **kwargs):
        try:
            
            account = TradingAccount.objects.get(account_id=mam_id, user=request.user)

            
            withdrawable_amount = MT5ManagerActions().get_balance(int(account.account_id))

            
            from clientPanel.models import BankDetails
            bank_details = None
            bank_status = None
            crypto_details = None

            # Always fetch the user's approved bank details directly

            import logging
            logger = logging.getLogger(__name__)
            bank_details_obj = BankDetails.objects.filter(user=request.user, status='approved').first()

            available_methods = []
            if bank_details_obj:
                bank_details = BankDetailsSerializer(bank_details_obj).data
                bank_status = bank_details.get('status')
                available_methods.append('bank')


            if hasattr(request.user, "crypto_details"):
                crypto_details_obj = request.user.crypto_details
                crypto_details = CryptoDetailsSerializer(crypto_details_obj).data
                if crypto_details.get('status') == 'approved':
                    available_methods.append('crypto')

            response_data = {
                "success": True,
                "data": {
                    "withdrawable_amount": withdrawable_amount,
                    "bank_details": bank_details,
                    "bank_details_status": bank_status,
                    "crypto_details": crypto_details,
                    "available_methods": available_methods,
                }
            }
            if not bank_details:
                logger.warning(f"[WithdrawInfoView] No approved bank details found for user {request.user.id} ({request.user.username})")
            return Response(
                response_data,
                status=status.HTTP_200_OK,
            )
        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Trading account not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class WithdrawRequestView(APIView):
    """
    Handles withdrawal requests for an account.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            mam_id = request.data.get("mam_id")
            amount = request.data.get("amount")
            method = request.data.get("method")


            if not mam_id or not amount or not method:
                return Response(
                    {"error": "mam_id, amount, and method are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # If method is bank, check that user's bank details are approved
            if method.lower() == 'bank':
                from clientPanel.models import BankDetails
                bank_details = BankDetails.objects.filter(user=request.user, status='approved').first()
                if not bank_details:
                    return Response(
                        {"error": "No bank details found. Please add your bank details first and wait for approval."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            
            account = TradingAccount.objects.get(account_id=mam_id, user=request.user)

            
            withdrawable_amount = account.balance
            if Decimal(amount) > withdrawable_amount:
                return Response(
                    {"error": "Requested amount exceeds withdrawable balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            
            transaction = Transaction.objects.create(
                user=request.user,
                trading_account=account,
                transaction_type="withdraw_trading",
                amount=Decimal(amount),
                status="pending",  
                source=method.capitalize(),
                description=f"Withdrawal request via {method.capitalize()}",
                migrated_to_old_withdrawal=False,
            )
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Submitted a withdrawal request for account {mam_id} with amount {amount} via {method.capitalize()}.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=account.id,
                related_object_type="TradingAccount",
            )

            return Response(
                {"message": "Withdrawal request submitted successfully.", "transaction_id": transaction.id},
                status=status.HTTP_201_CREATED,
            )
        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Trading account not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserDetailsWithDocumentsView(APIView):
    """
    View to fetch user details along with associated proof documents.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        
        user = request.user

        
        user_serializer = UserSerializer(user)

        
        return Response({
            "user_details": user_serializer.data
        }, status=200)

class BankDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            bank_details = BankDetails.objects.get(user=request.user)
            serializer = BankDetailsSerializer(bank_details)
            return Response({
                "status": "success",
                "message": "Bank details found",
                **serializer.data
            }, status=status.HTTP_200_OK)
            
        except BankDetails.DoesNotExist:
            logger.info(f"No bank details found for user: {request.user.username}")
            return Response({
                "status": "not_found",
                "message": "Bank details not found",
                "bank_name": None,
                "account_number": None,
                "branch_name": None,
                "ifsc_code": None,
                "bank_doc": None
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            import traceback
            logger.error(f"Error in BankDetailsView: {str(e)}")
            logger.error(f"User: {request.user.username}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            
            # Check if database connection is working
            from django.db import connection
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT 1")
            except Exception as db_error:
                logger.error(f"Database error: {str(db_error)}")
            
            return Response(
                {
                    "error": "Failed to fetch bank details",
                    "detail": str(e),
                    "status": "error"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class BankDetailsRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        serializer = BankDetailsRequestSerializer(data=data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            ActivityLog.objects.create(
                user=request.user,
                activity="Submitted a bank details request.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=serializer.instance.id,
                related_object_type="BankDetailsRequest",
            )

            return Response(
                {"message": "Bank details request submitted successfully."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CryptoDetailsRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Submit crypto details for admin approval"""
        try:
            data = request.data
            
            # Validate required fields
            if 'wallet_address' not in data or not data['wallet_address'].strip():
                return Response(
                    {'error': 'Wallet address is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create a new crypto details request (using CryptoDetails model)
            crypto_details, created = CryptoDetails.objects.get_or_create(
                user=request.user,
                defaults={
                    'wallet_address': data['wallet_address'].strip(),
                    'currency': data.get('currency', 'BTC'),
                    'status': 'pending'  # Set status to pending for admin approval
                }
            )
            
            if not created:
                # Update existing record and reset status to pending
                crypto_details.wallet_address = data['wallet_address'].strip()
                if 'currency' in data:
                    crypto_details.currency = data['currency']
                crypto_details.status = 'pending'
                crypto_details.save()
            
            ActivityLog.objects.create(
                user=request.user,
                activity="Submitted crypto details request for admin approval.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create" if created else "update",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=crypto_details.id,
                related_object_type="CryptoDetails",
            )

            return Response(
                {"message": "Crypto details request submitted successfully. Awaiting admin approval."},
                status=status.HTTP_201_CREATED,
            )
            
        except Exception as e:
            return Response(
                {"error": f"Failed to submit crypto details request: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class CryptoDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            crypto_details = CryptoDetails.objects.get(user=request.user)
            serializer = CryptoDetailsSerializer(crypto_details)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except CryptoDetails.DoesNotExist:
            return Response(
                {"error": "Crypto details not found."},
                status=status.HTTP_200_OK,
            )

    def post(self, request):
        try:
            crypto_details, created = CryptoDetails.objects.update_or_create(
                user=request.user,
                defaults={
                    "wallet_address": request.data.get("wallet_address", ""),
                    "currency": request.data.get("currency", ""),
                },
            )
            # If record existed and currency was provided, ensure it's updated and status reset
            if not created and request.data.get("currency"):
                try:
                    crypto_details.currency = request.data.get("currency")
                    crypto_details.status = 'pending'
                    crypto_details.save()
                except Exception:
                    # don't block user if saving currency fails; log elsewhere if needed
                    pass
            serializer = CryptoDetailsSerializer(crypto_details)
            ActivityLog.objects.create(
                user=request.user,
                activity="Updated crypto details.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="update",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=crypto_details.id,
                related_object_type="CryptoDetails",
            )

            return Response(
                {"message": "Crypto details updated successfully.", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to update crypto details. {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

class AccountSettingsView(APIView):
    def get(self, request, mam_id):
        account = get_object_or_404(TradingAccount, account_id=mam_id)
        return Response(
            {
                "current_leverage": account.leverage,
                "is_trading_enabled": account.is_trading_enabled,
            },
            status=status.HTTP_200_OK,
        )

class UpdateLeverageView(APIView):
    def post(self, request, mam_id):
        try:
            account = get_object_or_404(TradingAccount, account_id=mam_id)
            leverage = str(request.data.get("leverage"))
            if leverage not in ["1", "2", "5", "10", "20", "50", "100", "200", "500", "1000"]:
                return Response(
                    {"error": "Invalid leverage value."}, status=status.HTTP_400_BAD_REQUEST
                )
            if MT5ManagerActions().change_leverage(int(mam_id), int(leverage)):
                account.leverage = leverage
                account.save()
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Updated leverage for account {account.account_id} to {leverage}.",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="update",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=account.id,
                    related_object_type="TradingAccount",
                )

                return Response(
                    {"message": "Leverage updated successfully.", "leverage": account.leverage},
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response({"message": str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR,)

class ClientUpdateLeverageView(APIView):
    """
    API endpoint for clients to update their trading account leverage
    Endpoint: POST /api/update-leverage/{account_id}/
    Request body: { "leverage": "100" }
    """
    def post(self, request, account_id):
        try:
            # Get and verify account ownership
            account = get_object_or_404(TradingAccount, account_id=account_id, user=request.user)
            
            leverage = request.data.get("leverage")
            if not leverage or str(leverage) not in ["1", "2", "5", "10", "20", "50", "100", "200", "500", "1000"]:
                return Response(
                    {"error": "Invalid leverage value."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            if MT5ManagerActions().change_leverage(int(account_id), int(leverage)):
                account.leverage = leverage
                account.save()
                
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Updated leverage for account {account.account_id} to {leverage}.",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="update",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=account.id,
                    related_object_type="TradingAccount",
                )

                # Return format matching what manage.js expects for handleLeverageUpdate
                return Response({
                    "success": True,
                    "message": "Leverage updated successfully",
                    "data": {
                        "leverage": leverage,
                        "account_id": account_id
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to update leverage in MT5"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Account not found or you don't have permission to modify it."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ClientUpdatePasswordView(APIView):
    """
    API endpoint for clients to update their trading account password
    Endpoint: POST /api/update-password/{account_id}/
    Request body: { "new_password": "password123" }
    """
    def post(self, request, account_id):
        try:
            # Get and verify account ownership
            account = get_object_or_404(TradingAccount, account_id=account_id, user=request.user)
            
            new_password = request.data.get("new_password")
            if not new_password or len(new_password) < 8:
                return Response(
                    {"error": "Password must be at least 8 characters long."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Remove account_id from request body since it's in the URL
            if MT5ManagerActions().change_master_password(int(account_id), new_password):
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Updated master password for account {account.account_id}.",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="update",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=account.id,
                    related_object_type="TradingAccount",
                )

                # Return format matching what manage.js expects for handlePasswordUpdate
                return Response({
                    "success": True,
                    "message": "Password updated successfully",
                    "data": {
                        "account_id": account_id
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to update password in MT5"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Account not found or you don't have permission to modify it."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def signup_view(request):
    if request.method == "POST":
        first_name = request.POST.get("firstName")
        last_name = request.POST.get("lastName")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirmPassword")
        referrer = request.POST.get("referrer")  

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("signup")

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email is already in use.")
            return redirect("signup")
        ibuser = CustomUser.objects.get(user_id = referrer)
        if ibuser.IB_status:
            user = CustomUser.objects.create_user(
                username=email,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number = phone,
                password=password,
                parent_ib = ibuser,
                
            )
        else:
            user = CustomUser.objects.create_user(
                username=email,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number = phone,
                password=password,
            )
            
        messages.success(request, "User created successfully. Please log in.")
        return redirect("login")  # Redirect to login page after successful registration

    return render(request, "emails/signup.html")

from bs4 import BeautifulSoup

class USDINRRateView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            url = "https://www.google.com/finance/quote/USD-INR"
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            rate = soup.find("div", {"class": "YMlKec fxKbKc"}).text.strip().replace("₹", "").replace(",", "")
            return Response({'rate': float(rate)}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'Scraping failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Test endpoint for debugging authentication
class AuthTestView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    def post(self, request):
        return Response({
            "success": True,
            "user": str(request.user),
            "authenticated": request.user.is_authenticated,
            "data_received": request.data
        })



# ===== CheezePay Integration Functions =====

# CheezePay configuration
import time
import requests

# CheezePay Configuration - Load from environment variables
CHEEZEPAY_MERCHANT_ID = os.getenv('CHEEZEPAY_MERCHANT_ID', 'CH10001079')
CHEEZEPAY_APP_ID = os.getenv('CHEEZEPAY_APP_ID', 'u7b14kc4pNbc')
CHEEZEPAY_PAYIN_URL = os.getenv('CHEEZEPAY_PAYIN_URL', 'https://api-cheezeepay-india.cheezeebit.com/payment/india/order/create/v1')
CHEEZEPAY_NOTIFY_URL = os.getenv('CHEEZEPAY_NOTIFY_URL', 'https://client.vtindex.com/client/cheezepay-notify/')
CHEEZEPAY_RETURN_URL = os.getenv('CHEEZEPAY_RETURN_URL', 'https://client.vtindex.com/dashboard')

# Load RSA keys for CheezePay
def load_cheezepay_private_key():
    """Load merchant private key for signing requests"""
    try:
        key_path = os.path.join(settings.BASE_DIR, 'CheezeePay', 'merchant_private_key.pem')
        with open(key_path, 'rb') as key_file:
            return load_pem_private_key(key_file.read(), password=None)
    except Exception as e:
        logger.error(f"Failed to load private key: {e}")
        raise

def load_cheezepay_public_key():
    """Load platform public key for verifying responses"""
    try:
        key_path = os.path.join(settings.BASE_DIR, 'CheezeePay', 'platform_public_key.pem')
        with open(key_path, 'rb') as key_file:
            return load_pem_public_key(key_file.read())
    except Exception as e:
        logger.error(f"Failed to load public key: {e}")
        raise

# Initialize keys
try:
    cheezepay_private_key = load_cheezepay_private_key()
    cheezepay_public_key = load_cheezepay_public_key()
except Exception as e:
    logger.error(f"Failed to initialize CheezePay keys: {e}")
    cheezepay_private_key = None
    cheezepay_public_key = None

def create_signature_string(data):
    """
    Creates a signature string following CheezePay requirements:
    1. Get request parameters, excluding 'sign' field and parameters with empty values
    2. Sort in ascending order by ASCII code values of keys (alphabetical order)
    3. Combine sorted parameters in format: parameter=value
    4. Connect parameters with '&' character
    """
    # Step 1: Filter out 'sign' field and empty values
    filtered_data = {k: v for k, v in data.items() if k != "sign" and v}
    
    # Step 2: Sort keys by ASCII order (alphabetical)
    sorted_keys = sorted(filtered_data.keys())
    
    # Step 3 & 4: Create parameter=value pairs and join with '&'
    signature_string = "&".join(f"{key}={filtered_data[key]}" for key in sorted_keys)
    
    return signature_string

def sign_data(data):
    """Generate RSA signature for request data"""
    try:
        signature_string = create_signature_string(data)
        
        signature = cheezepay_private_key.sign(
            signature_string.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to sign data: {e}")
        raise

def verify_signature(data, received_signature):
    """Verify RSA signature from platform response"""
    try:
        signature_string = create_signature_string(data)
        
        decoded_signature = base64.b64decode(received_signature)
        
        cheezepay_public_key.verify(
            decoded_signature,
            signature_string.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def pay_in(amount, phone, name, email, transactionid):
    """
    Initiate payment request to CheezePay
    
    Args:
        amount (int): Amount in paise (smallest currency unit)
        phone (str): Customer phone number
        name (str): Customer name
        email (str): Customer email
        transactionid (int): Internal transaction ID
        
    Returns:
        dict: Payment response or None if failed
    """
    try:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"
        }
        
        # Prepare payment data
        # Some gateways append parameters starting with '&' to the notify/return URL.
        # To avoid malformed URLs on our side (e.g., /notify/&param=...), ensure the
        # provided notify/return URLs already contain a '?' so appended params form a
        # proper query string. Do not modify the env vars themselves; just adjust
        # the values sent in this request.
        def ensure_query_marker(url):
            if not url:
                return url
            # If url already contains a '?' or ends with '?', leave as-is
            return url if '?' in url else url + '?'

        notify_url_to_send = ensure_query_marker(CHEEZEPAY_NOTIFY_URL)
        return_url_to_send = ensure_query_marker(CHEEZEPAY_RETURN_URL)


        data = {
            "appId": CHEEZEPAY_APP_ID,
            "merchantId": CHEEZEPAY_MERCHANT_ID,
            "mchOrderNo": str(transactionid),
            "paymentMode": "P2P",
            "amount": str(amount),
            "name": name,
            "phone": phone,
            "email": email,
            "notifyUrl": notify_url_to_send,
            "returnUrl": return_url_to_send,
            "language": "en",
            "timestamp": str(int(time.time() * 1000)),
        }
        
        # Generate signature
        data["sign"] = sign_data(data)
    
        
        # Make API request
        response = requests.post(CHEEZEPAY_PAYIN_URL, json=data, headers=headers, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        
        # Check response status
        if result.get("code") == "000000":  # Success
            # Verify response signature if present
            if result.get("sign"):
                if verify_signature(result, result["sign"]):
                    return result
                else:
                    logger.error("Payment response signature verification failed")
                    return None
            else:
                logger.warning("No signature in payment response - proceeding without verification")
                return result
        else:
            logger.error(f"Payment initiation failed: {result.get('msg', 'Unknown error')}")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during payment initiation: {e}")
        return None
    except Exception as e:
        logger.error(f"Error initiating payment: {e}")
        return None


# ===== CheezePay Notification Handler =====

@method_decorator(csrf_exempt, name='dispatch')
class CheesePayNotifyView(APIView):
    """
    Handles payment notification webhooks from CheezePay
    Processes payment status updates and updates transaction records
    """
    permission_classes = []  # No authentication required for webhooks

    def dispatch(self, request, *args, **kwargs):
        """Wrap dispatch to guarantee a Response is returned.

        Some unexpected errors or middleware interactions can cause the view
        to return None which DRF treats as an invalid return type. Wrap the
        normal dispatch and convert None into a 500 JSON response while
        logging the context for easier debugging.
        """
        try:
            result = super().dispatch(request, *args, **kwargs)
        except Exception as e:
            logger.exception(f"Exception in CheesePayNotifyView.dispatch: {e}")
            return Response({"error": "Internal server error in webhook"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # If the view returned None for any reason, log and return 500
        if result is None:
            logger.error("CheesePayNotifyView.dispatch: view returned None — converting to 500 Response")
            return Response({"error": "Internal server error - no response from view"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return result

    def post(self, request, *args, **kwargs):
        try:
            # Prefer DRF-parsed data which handles JSON and form-encoded bodies
            data = None
            try:
                if hasattr(request, 'data') and request.data:
                    data = request.data
            except Exception:
                data = None

            # Fallback: try raw JSON body
            if not data:
                try:
                    body_text = request.body.decode('utf-8') if isinstance(request.body, (bytes, bytearray)) else request.body
                    data = json.loads(body_text) if body_text and body_text.strip() else {}
                except Exception:
                    # Final fallback: use form-encoded POST params
                    data = {k: request.POST.get(k) for k in request.POST.keys()}

            # Ensure we have a plain dict
            if not isinstance(data, dict):
                try:
                    data = dict(data)
                except Exception:
                    data = {}

            # Extract parameters (support multiple naming conventions)
            merchant_id = data.get("merchantId") or data.get("merchant_id")
            mch_order_no = data.get("mchOrderNo") or data.get("mch_order_no") or data.get("mchOrder") or data.get("mch_order")
            plat_order_no = data.get("platOrderNo") or data.get("plat_order_no")
            order_status = data.get("orderStatus") or data.get("order_status")
            pay_amount = data.get("payAmount") or data.get("pay_amount")
            amount_currency = data.get("amountCurrency") or data.get("amount_currency")
            fee = data.get("fee")
            fee_currency = data.get("feeCurrency") or data.get("fee_currency")
            payer_upi_id = data.get("payerUpiId") or data.get("payer_upi_id") or ""
            gmt_end = data.get("gmtEnd") or data.get("gmt_end")
            received_signature = data.get("sign") or data.get("signature") or None


            # Verify merchant ID (support config in settings or module-level constant)
            expected_merchant = None
            try:
                expected_merchant = getattr(settings, 'CHEESEPAY_CONFIG', {}).get('MERCHANT_ID')
            except Exception:
                expected_merchant = None
            if not expected_merchant:
                expected_merchant = globals().get('CHEEZEPAY_MERCHANT_ID') or globals().get('CHEEZEPAY_MERCHANT_ID')

            if merchant_id != expected_merchant:
                logger.warning(f"CheezePay notify: invalid merchant id. got={merchant_id} expected={expected_merchant}")
                return Response({"error": "Invalid merchant ID"}, status=status.HTTP_400_BAD_REQUEST)

            # Verify Signature
            if not received_signature or not self.verify_signature(data, received_signature):
                logger.warning('CheezePay notify: signature verification failed')
                return Response({"error": "Signature verification failed"}, status=status.HTTP_400_BAD_REQUEST)

            # Normalize order_status to int if possible (CheezePay may send strings)
            try:
                order_status = int(order_status)
            except Exception:
                try:
                    order_status = int(float(order_status))
                except Exception:
                    order_status = None

            # Normalize transaction id to int when possible
            mch_lookup_id = mch_order_no
            try:
                mch_lookup_id = int(mch_order_no)
            except Exception:
                pass

            # Select transaction for update (locking the row)
            with db_transaction.atomic():
                transaction = Transaction.objects.select_for_update().filter(id=mch_lookup_id).first()

                if not transaction:
                    logger.warning(f"CheezePay notify: transaction not found (mch_order_no={mch_order_no})")
                    return Response({"error": "Transaction not found"}, status=status.HTTP_404_NOT_FOUND)

                # Successful payment
                if order_status == 1:
                    if transaction.status == 'pending':
                        mt5action = MT5ManagerActions()
                        success = False
                        try:
                            success = mt5action.deposit_funds(transaction.trading_account.account_id, transaction.amount, f"CheezeePay | {plat_order_no}")
                        except Exception as e:
                            logger.exception(f"Error depositing funds into MT5 for transaction {transaction.id}: {e}")

                        if success:
                            transaction.status = "approved"
                            transaction.description = f"CheezeePay | {plat_order_no}"
                            # mark approval time for consistency with admin approvals
                            try:
                                transaction.approved_at = now()
                            except Exception:
                                # fallback: ignore if now() unavailable for some reason
                                pass
                            transaction.save()
                            # Send deposit confirmation email to the user (best-effort)
                            try:
                                user = getattr(transaction, 'user', None)
                                if user and getattr(user, 'email', None):
                                    # Use EmailSender utility - import exists at module top
                                    EmailSender.send_deposit_confirmation(
                                        user.email,
                                        getattr(user, 'username', '') or getattr(user, 'first_name', ''),
                                        transaction.trading_account.account_id if transaction.trading_account else None,
                                        transaction.amount,
                                        transaction.id,
                                        transaction.approved_at.strftime('%Y-%m-%d %H:%M:%S') if getattr(transaction, 'approved_at', None) else ''
                                    )
                            except Exception as email_exc:
                                logger.exception(f"Failed to send deposit confirmation email for transaction {transaction.id}: {email_exc}")

                            try:
                                del mt5action
                            except Exception:
                                pass

                            return Response({"message": "Payment received and processed"}, status=status.HTTP_200_OK)

                        # If deposit to MT5 failed, ask for retry
                        return Response({"error": "Retry"}, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        # Idempotency: if transaction already processed, return 200 OK
                        logger.info(f"CheezePay notify: transaction {transaction.id} already processed (status={transaction.status})")
                        return Response({"message": "Transaction already processed"}, status=status.HTTP_200_OK)

                elif order_status == 3:
                    return Response({"message": "Partial payment recorded"}, status=status.HTTP_200_OK)

                elif order_status == 2:
                    return Response({"message": "Refund processed"}, status=status.HTTP_200_OK)

                else:
                    logger.warning(f"CheezePay notify: unknown order status: {order_status}")
                    return Response({"error": "Unknown order status"}, status=status.HTTP_400_BAD_REQUEST)

        except json.JSONDecodeError:
            return Response({"error": "Invalid JSON"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def verify_signature(self, data, received_signature):
        """Verify RSA signature from platform notification"""
        try:
            # Remove 'sign' field from data for verification
            data_for_verification = {k: v for k, v in data.items() if k != "sign"}
            signature_string = create_signature_string(data_for_verification)
            
            decoded_signature = base64.b64decode(received_signature)
            
            cheezepay_public_key.verify(
                decoded_signature,
                signature_string.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
        

    def get(self, request, *args, **kwargs):
        """Handle GET requests for testing purposes"""
        return Response({"message": "CheezePay notification endpoint is active"}, status=status.HTTP_200_OK)
