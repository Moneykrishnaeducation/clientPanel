# Enhanced Withdrawal Views with Full Database Integration
from decimal import Decimal
from django.db import transaction
from django.utils.timezone import now
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from adminPanel.models import (
    CustomUser, TradingAccount, Transaction, ActivityLog, 
    CryptoDetails
)
from clientPanel.models import BankDetails
from adminPanel.serializers import TradingAccountSerializer
from adminPanel.mt5.services import MT5ManagerActions
from adminPanel.views.views import get_client_ip
from django.shortcuts import get_object_or_404

class WithdrawalInfoView(APIView):
    """
    Enhanced view to provide comprehensive withdrawal information including:
    - Account balance and withdrawable amount
    - User's verified bank details
    - User's verified crypto details
    - Available withdrawal methods
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, account_id=None, *args, **kwargs):
        try:
            # Get account ID from URL parameter or request data
            if not account_id:
                account_id = request.query_params.get('account_id')
            
            if not account_id:
                return Response(
                    {"error": "Account ID is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get the trading account
            account = get_object_or_404(
                TradingAccount, 
                account_id=account_id, 
                user=request.user
            )

            # Get real-time balance from MT5
            mt5_manager = MT5ManagerActions()
            try:
                current_balance = mt5_manager.get_balance(int(account.account_id))
                current_equity = mt5_manager.get_equity(int(account.account_id))
                floating_pnl = mt5_manager.get_profit(int(account.account_id))
            except Exception as mt5_error:
                current_balance = float(account.balance)
                current_equity = float(account.balance)
                floating_pnl = 0.0

            # Calculate withdrawable amount (usually equity minus margin requirement)
            withdrawable_amount = max(0, current_equity)

            # Get user's approved bank details
            bank_details = None
            try:
                # Debug: Check all bank details for this user
                all_bank_details = BankDetails.objects.filter(user=request.user)
                
                # Check specifically for approved ones
                approved_bank_details = BankDetails.objects.filter(user=request.user, status='approved')
                
                bank_detail = approved_bank_details.first()
                if bank_detail:
                    bank_details = {
                        'bank_name': bank_detail.bank_name,
                        'account_number': bank_detail.account_number,
                        'branch_name': bank_detail.branch_name,
                        'ifsc_code': bank_detail.ifsc_code,
                        'status': bank_detail.status,
                        'is_verified': True
                    }
            except BankDetails.DoesNotExist:
                pass

            # Get user's crypto details
            crypto_details = None
            try:
                crypto_detail = CryptoDetails.objects.get(user=request.user)
                crypto_details = {
                    'wallet_address': crypto_detail.wallet_address,
                    'currency': crypto_detail.currency,
                    'exchange_name': crypto_detail.exchange_name,
                    'status': crypto_detail.status,
                    'is_verified': crypto_detail.status == 'approved'
                }
            except CryptoDetails.DoesNotExist:
                pass

            # Determine available withdrawal methods
            available_methods = []
            if bank_details and bank_details['is_verified']:
                available_methods.append('bank')
            if crypto_details and crypto_details['is_verified']:
                available_methods.append('crypto')

            # Get recent withdrawal history
            recent_withdrawals = Transaction.objects.filter(
                user=request.user,
                trading_account=account,
                transaction_type='withdraw_trading'
            ).order_by('-created_at')[:5]

            withdrawal_history = []
            for txn in recent_withdrawals:
                withdrawal_history.append({
                    'id': txn.id,
                    'amount': float(txn.amount),
                    'status': txn.status,
                    'method': txn.source,
                    'created_at': txn.created_at,
                    'description': txn.description
                })

            return Response({
                'success': True,
                'data': {
                    'account_id': account.account_id,
                    'account_type': account.account_type,
                    'current_balance': current_balance,
                    'current_equity': current_equity,
                    'floating_pnl': floating_pnl,
                    'withdrawable_amount': withdrawable_amount,
                    'bank_details': bank_details,
                    'crypto_details': crypto_details,
                    'available_methods': available_methods,
                    'recent_withdrawals': withdrawal_history,
                    'minimum_withdrawal': 10.0,  # Set minimum withdrawal amount
                    'withdrawal_fee': 0.0  # Set withdrawal fee if applicable
                }
            }, status=status.HTTP_200_OK)

        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Trading account not found or you don't have access to it"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to get withdrawal information: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class WithdrawalRequestView(APIView):
    """
    Enhanced withdrawal request handling with comprehensive validation
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Enforce KYC check before any withdrawal
            user = request.user
            if not hasattr(user, 'user_verified') or not user.user_verified:
                # Log blocked withdrawal attempt
                ActivityLog.objects.create(
                    user=user,
                    activity=f"Blocked withdrawal attempt: KYC incomplete for user {user.email}",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="create",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                )
                return Response(
                    {"error": "Withdrawal blocked: Please complete KYC verification before making withdrawals."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Extract and validate request data
            account_id = request.data.get("account_id")
            amount = request.data.get("amount")
            method = request.data.get("method")  # 'bank' or 'crypto'
            description = request.data.get("description", "")

            # Validation
            if not account_id:
                return Response(
                    {"error": "Account ID is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not amount:
                return Response(
                    {"error": "Withdrawal amount is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not method or method not in ['bank', 'crypto']:
                return Response(
                    {"error": "Valid withdrawal method (bank/crypto) is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                amount = Decimal(str(amount))
                if amount <= 0:
                    raise ValueError("Amount must be positive")
            except (ValueError, TypeError):
                return Response(
                    {"error": "Invalid amount format"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get the trading account
            account = get_object_or_404(
                TradingAccount, 
                account_id=account_id, 
                user=request.user
            )

            # Verify withdrawal method availability
            if method == 'bank':
                try:
                    bank_details = BankDetails.objects.get(user=request.user)
                    if bank_details.status != 'approved':
                        return Response(
                            {"error": "Bank details are not verified. Please verify your bank details first."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except BankDetails.DoesNotExist:
                    return Response(
                        {"error": "No bank details found. Please add your bank details first."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            elif method == 'crypto':
                try:
                    crypto_details = CryptoDetails.objects.get(user=request.user)
                    if crypto_details.status != 'approved':
                        return Response(
                            {"error": "Crypto details are not verified. Please verify your crypto details first."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except CryptoDetails.DoesNotExist:
                    return Response(
                        {"error": "No crypto details found. Please add your crypto details first."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Check available balance
            mt5_manager = MT5ManagerActions()
            try:
                current_equity = mt5_manager.get_equity(int(account.account_id))
                withdrawable_amount = max(0, current_equity)
            except Exception:
                # Fallback to database balance if MT5 is unavailable
                withdrawable_amount = float(account.balance)

            if amount > Decimal(str(withdrawable_amount)):
                return Response(
                    {
                        "error": f"Insufficient withdrawable balance. Available: {withdrawable_amount:.2f}",
                        "available_amount": withdrawable_amount
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Minimum withdrawal check
            minimum_withdrawal = Decimal('10.00')
            if amount < minimum_withdrawal:
                return Response(
                    {"error": f"Minimum withdrawal amount is {minimum_withdrawal}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create withdrawal transaction
            with transaction.atomic():
                withdrawal_transaction = Transaction.objects.create(
                    user=request.user,
                    trading_account=account,
                    transaction_type="withdraw_trading",
                    amount=amount,
                    status="pending",
                    source=method.capitalize(),
                    description=description or f"Withdrawal request via {method.capitalize()} - {account_id}"
                )

                # Log the activity
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Submitted withdrawal request for {amount} from account {account_id} via {method}",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="create",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=account.id,
                    related_object_type="TradingAccount"
                )

            return Response({
                "success": True,
                "message": "Withdrawal request submitted successfully and is pending approval",
                "data": {
                    "transaction_id": withdrawal_transaction.id,
                    "account_id": account_id,
                    "amount": float(amount),
                    "method": method,
                    "status": "pending",
                    "created_at": withdrawal_transaction.created_at
                }
            }, status=status.HTTP_201_CREATED)

        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Trading account not found or you don't have access to it"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to process withdrawal request: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserPaymentDetailsView(APIView):
    """
    Enhanced view to manage user's bank and crypto details for withdrawals
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """Get user's bank and crypto details"""
        try:
            response_data = {
                'bank_details': None,
                'crypto_details': None
            }

            # Get bank details
            try:
                bank_details = BankDetails.objects.get(user=request.user)
                response_data['bank_details'] = {
                    'bank_name': bank_details.bank_name,
                    'account_number': bank_details.account_number,
                    'branch_name': bank_details.branch_name,
                    'ifsc_code': bank_details.ifsc_code,
                    'status': bank_details.status,
                    'created_at': bank_details.created_at,
                    'updated_at': bank_details.updated_at
                }
            except BankDetails.DoesNotExist:
                pass

            # Get crypto details
            try:
                crypto_details = CryptoDetails.objects.get(user=request.user)
                response_data['crypto_details'] = {
                    'wallet_address': crypto_details.wallet_address,
                    'currency': crypto_details.currency,
                    'exchange_name': crypto_details.exchange_name,
                    'status': crypto_details.status,
                    'created_at': crypto_details.created_at,
                    'updated_at': crypto_details.updated_at
                }
            except CryptoDetails.DoesNotExist:
                pass

            return Response({
                'success': True,
                'data': response_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to get payment details: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class WithdrawalHistoryView(APIView):
    """
    View to get user's withdrawal history with pagination
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            # Get query parameters
            account_id = request.query_params.get('account_id')
            page = int(request.query_params.get('page', 1))
            limit = int(request.query_params.get('limit', 10))
            status_filter = request.query_params.get('status')

            # Build query
            query = Transaction.objects.filter(
                user=request.user,
                transaction_type='withdraw_trading'
            )

            if account_id:
                query = query.filter(trading_account__account_id=account_id)

            if status_filter:
                query = query.filter(status=status_filter)

            # Order by created date (newest first)
            query = query.order_by('-created_at')

            # Calculate pagination
            total_count = query.count()
            offset = (page - 1) * limit
            withdrawals = query[offset:offset + limit]

            # Format response
            withdrawal_list = []
            for withdrawal in withdrawals:
                withdrawal_list.append({
                    'id': withdrawal.id,
                    'account_id': withdrawal.trading_account.account_id if withdrawal.trading_account else None,
                    'amount': float(withdrawal.amount),
                    'method': withdrawal.source,
                    'status': withdrawal.status,
                    'description': withdrawal.description,
                    'created_at': withdrawal.created_at,
                    'approved_by': withdrawal.approved_by.username if withdrawal.approved_by else None
                })

            return Response({
                'success': True,
                'data': {
                    'withdrawals': withdrawal_list,
                    'pagination': {
                        'page': page,
                        'limit': limit,
                        'total_count': total_count,
                        'total_pages': (total_count + limit - 1) // limit
                    }
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to get withdrawal history: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
