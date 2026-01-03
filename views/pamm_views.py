"""
PAMM Views for API endpoints
"""
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
import logging

from ..models import PAMAccount, PAMInvestment
from ..serializers import (
    PAMAccountSerializer, PAMAccountCreateSerializer,
    PAMInvestmentSerializer, PAMInvestmentCreateSerializer,
    AvailablePAMAccountSerializer
)
from ..services.pamm_service import PAMMService
from decimal import Decimal
from django.shortcuts import get_object_or_404
from adminPanel.models import TradingAccount, Transaction
try:
    from adminPanel.models import ActivityLog
except Exception:
    ActivityLog = None
from django.utils.timezone import now
# The original code expected a helper `has_permission` to be importable from
# adminPanel.permissions. The adminPanel.permissions module exposes
# permission classes instead. Provide a small compatibility helper here to
# perform the same basic checks used across the codebase (superuser or
# manager_admin_status contains the role string).
def has_permission(user, permission_name: str) -> bool:
    """Compatibility helper: simple role check used by PAMM views.

    This mirrors the existing permission checks (superuser or
    manager_admin_status containing role name). Keep minimal to avoid
    importing permission classes at module import time.
    """
    if not user:
        return False
    try:
        if getattr(user, 'is_superuser', False):
            return True
        status = getattr(user, 'manager_admin_status', '')
        
        # Admin and Manager roles have full PAMM permissions
        if status and status.lower() in ['admin', 'manager']:
            return True
            
        # Client users can access PAMM (view, invest, manage their own)
        if status and status.lower() in ['client'] and permission_name.lower() in ['can_view_pamm', 'can_create_pamm']:
            return True
            
        # For users with None status, treat as client (common case)
        if not status or status == 'None':
            if permission_name.lower() in ['can_view_pamm', 'can_create_pamm']:
                return True
            
        # Check if specific permission is in status string
        if status and permission_name.lower() in status.lower():
            return True
    except Exception:
        return False
    return False

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def managed_pamm_list(request):
    """Get user's managed PAMM accounts"""
    try:
        # Check if user has permission to view PAMM accounts
        if not has_permission(request.user, 'can_view_pamm'):
            return Response(
                {'error': 'You do not have permission to view PAMM accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        pamm_accounts = PAMMService.get_user_managed_pamm_accounts(request.user)
        serializer = PAMAccountSerializer(pamm_accounts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error fetching managed PAMM accounts: {e}")
        return Response(
            {'error': 'Failed to fetch PAMM accounts'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def create_pamm_account(request):
    """Create a new PAMM account"""
    try:
        # Check if user has permission to create PAMM accounts
        if not has_permission(request.user, 'can_create_pamm'):
            return Response(
                {'error': 'You do not have permission to create PAMM accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = PAMAccountCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Create PAMM account using service
        success, result, error = PAMMService.create_pamm_account(
            user=request.user,
            data=serializer.validated_data
        )

        if not success:
            return Response(
                {'error': error},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Return created account data
        response_serializer = PAMAccountSerializer(result)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.error(f"Error creating PAMM account: {e}")
        return Response(
            {'error': 'Failed to create PAMM account'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def available_pamm_list(request):
    """Get available PAMM accounts for investment (exclude user's own accounts)"""
    try:
        # Check if user has permission to view PAMM accounts
        if not has_permission(request.user, 'can_view_pamm'):
            return Response(
                {'error': 'You do not have permission to view PAMM accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get available PAMM accounts excluding user's own accounts
        pamm_accounts = PAMMService.get_available_pamm_accounts(exclude_user=request.user)
        serializer = AvailablePAMAccountSerializer(pamm_accounts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error fetching available PAMM accounts: {e}")
        return Response(
            {'error': 'Failed to fetch available PAMM accounts'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_investments(request):
    """Get user's PAMM investments"""
    try:
        investments = PAMMService.get_user_investments(request.user)
        serializer = PAMInvestmentSerializer(investments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error fetching user investments: {e}")
        return Response(
            {'error': 'Failed to fetch investments'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def invest_in_pamm(request):
    """Invest in a PAMM account"""
    try:
        serializer = PAMInvestmentCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        pamm_id = serializer.validated_data['pamm_id']
        amount = serializer.validated_data['amount']

        # Create investment using service
        success, result, error = PAMMService.invest_in_pamm(
            user=request.user,
            pamm_id=pamm_id,
            amount=amount
        )

        if not success:
            return Response(
                {'error': error},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Return investment data
        response_serializer = PAMInvestmentSerializer(result)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.error(f"Error creating investment: {e}")
        return Response(
            {'error': 'Failed to create investment'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def disable_pamm_account(request):
    """Enable/disable a PAMM account"""
    try:
        pamm_id = request.data.get('pamm_id')
        enabled = request.data.get('enabled', False)

        if not pamm_id:
            return Response(
                {'error': 'PAMM ID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            pamm_account = PAMAccount.objects.get(id=pamm_id, manager=request.user)
        except PAMAccount.DoesNotExist:
            return Response(
                {'error': 'PAMM account not found or not owned by you'},
                status=status.HTTP_404_NOT_FOUND
            )

        pamm_account.enabled = enabled
        pamm_account.save()

        serializer = PAMAccountSerializer(pamm_account)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error updating PAMM account status: {e}")
        return Response(
            {'error': 'Failed to update PAMM account'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def leave_pamm_investment(request):
    """Leave a PAMM investment"""
    try:
        pamm_id = request.data.get('pamm_id')

        if not pamm_id:
            return Response(
                {'error': 'PAMM ID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            investment = PAMInvestment.objects.get(
                pam_account_id=pamm_id,
                investor=request.user
            )
        except PAMInvestment.DoesNotExist:
            return Response(
                {'error': 'Investment not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # In a real system, you might want to:
        # 1. Calculate final profit/loss
        # 2. Process withdrawal
        # 3. Send notification emails
        # 4. Update MT5 allocations

        investment.delete()

        return Response(
            {'message': 'Successfully left PAMM investment'},
            status=status.HTTP_200_OK
        )

    except Exception as e:
        logger.error(f"Error leaving PAMM investment: {e}")
        return Response(
            {'error': 'Failed to leave investment'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Placeholder views for deposit/withdraw (to be implemented based on existing system)
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def deposit_to_pamm(request):
    """Deposit funds to PAMM account"""
    # TODO: Implement based on existing deposit system
    return Response(
        {'message': 'Deposit functionality to be implemented'},
        status=status.HTTP_501_NOT_IMPLEMENTED
    )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def withdraw_from_pamm(request):
    """Withdraw funds from PAMM account"""
    # TODO: Implement based on existing withdrawal system
    return Response(
        {'message': 'Withdraw functionality to be implemented'},
        status=status.HTTP_501_NOT_IMPLEMENTED
    )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def deposit_to_pamm(request):
    """Investor-facing: submit a deposit request targeted at a PAMM (manager MT5 account).

    Body (form or JSON):
      - pamm_id: int (required)
      - amount: number/string (required)
      - proof: file (optional)

    This creates a pending Transaction whose `trading_account` is the PAMM manager's
    TradingAccount (looked up via PAMAccount.mt5_login). It does NOT auto-credit MT5;
    approval and processing remain an admin action.
    """
    try:
        pamm_id = request.data.get('pamm_id') or request.data.get('id')
        amount = request.data.get('amount')
        proof = request.FILES.get('proof')

        if not pamm_id or not amount:
            return Response({'error': 'pamm_id and amount are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount_dec = Decimal(str(amount))
            if amount_dec <= 0:
                raise ValueError()
        except Exception:
            return Response({'error': 'Invalid amount.'}, status=status.HTTP_400_BAD_REQUEST)

        pamm = get_object_or_404(PAMAccount, id=pamm_id)

        # Find manager trading account by mt5_login
        manager_account = TradingAccount.objects.filter(account_id=str(pamm.mt5_login)).first()
        if not manager_account:
            return Response({'error': 'PAMM manager trading account not found.'}, status=status.HTTP_404_NOT_FOUND)

        transaction = Transaction.objects.create(
            user=request.user,
            trading_account=manager_account,
            transaction_type='deposit_trading',
            amount=amount_dec,
            status='pending',
            description=f'PAMM deposit request to {pamm.name} (PAM {pamm.id})',
            source='PAMM'
        )

        if proof:
            transaction.document = proof
            transaction.save()

        # Optional ActivityLog (best-effort)
        try:
            if ActivityLog is not None:
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Submitted PAMM deposit request of {amount_dec} to PAMM {pamm.id} (manager acct {manager_account.account_id})",
                    ip_address=request.META.get('REMOTE_ADDR', ''),
                    endpoint=request.path,
                    activity_type='create',
                    activity_category='client',
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    timestamp=now(),
                    related_object_id=transaction.id,
                    related_object_type='Transaction'
                )
        except Exception:
            # Don't fail the request if logging fails
            pass

        return Response({'message': 'PAMM deposit request created.', 'transaction_id': transaction.id}, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.error(f"Error in deposit_to_pamm: {e}")
        return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
