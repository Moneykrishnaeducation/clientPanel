from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json
import logging
from decimal import Decimal, InvalidOperation
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction

from adminPanel.models import TradingAccount
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser

# Set up logging
logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_coefficient(request):
    """
    API endpoint to save the copy coefficient for MAM investments.
    Expected payload: 
    {
        "mode": "balance_ratio" or "fixed_multiple",
        "factor": "1.0" (decimal number),
        "account_id": "account_id_here"
    }
    """
    try:
        # Parse the request data
        data = request.data
        mode = data.get('mode')
        factor = data.get('factor')
        account_id = data.get('account_id')
        dual_trade_enabled = data.get('dual_trade_enabled', False)
        multi_trade_count = data.get('multi_trade_count', 1)  # New field

        # Convert mode from frontend values to database values if needed
        if mode == "balance":
            mode = "balance_ratio"
        elif mode == "fixed":
            mode = "fixed_multiple"

        # Log the received data
        logger.info(f"Received coefficient update: mode={mode}, factor={factor}, account_id={account_id}, dual_trade={dual_trade_enabled}, trade_count={multi_trade_count}")
        logger.info(f"Request user: {request.user.id}, Request data: {data}")

        # Validate the required fields
        if not mode or not account_id:
            return Response(
                {"error": "Missing required fields. 'mode' and 'account_id' are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate mode value
        if mode not in ["balance_ratio", "fixed_multiple"]:
            return Response(
                {"error": "Invalid mode. Mode must be either 'balance_ratio' or 'fixed_multiple'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check that factor is provided when mode is "fixed_multiple"
        if mode == "fixed_multiple" and not factor:
            return Response(
                {"error": "Factor is required when mode is 'fixed_multiple'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate factor is a numeric value
        try:
            if factor is not None:
                factor_decimal = Decimal(str(factor))
                if factor_decimal <= Decimal('0'):
                    return Response(
                        {"error": "Factor must be a positive number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                # Default to 1.0 for balance_ratio if not provided
                if mode == "balance_ratio":
                    factor_decimal = Decimal('1.0')
                else:
                    factor_decimal = None
        except (TypeError, ValueError, InvalidOperation):
            return Response(
                {"error": "Invalid factor. Must be a valid positive number."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Find the investment account by account_id
        try:
            account = TradingAccount.objects.get(account_id=account_id)
            logger.info(f"Found account: {account.account_id}, type: {account.account_type}, user: {account.user.id}")
            
            # Verify it's a MAM account (either manager or investment)
            if account.account_type not in ['mam', 'mam_investment']:
                return Response(
                    {"error": f"Account {account_id} is not a MAM account"},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Check if the user has permission to update this account
            # Allow if user owns the account OR if user is staff/admin
            if account.user != request.user and not request.user.is_staff:
                return Response(
                    {"error": "You do not have permission to update this account"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Update the coefficient settings
            account.copy_mode = mode
            account.copy_factor = factor_decimal
            account.dual_trade_enabled = dual_trade_enabled
            account.multi_trade_count = max(1, min(10, int(multi_trade_count)))  # Clamp between 1-10
            
            # Maintain legacy compatibility fields for older code paths
            try:
                if mode == 'fixed_multiple':
                    account.copy_multiplier_mode = 'fixed_multiple'
                    # fixed_copy_multiplier expects a numeric value
                    account.fixed_copy_multiplier = factor_decimal or Decimal('0.00')
                else:
                    account.copy_multiplier_mode = 'balance_ratio'
                    account.fixed_copy_multiplier = Decimal('0.00')
            except Exception:
                # Best-effort: continue even if compatibility fields cannot be set
                pass
            account.save()
            
            logger.info(f"Successfully saved coefficient: mode={mode}, factor={factor_decimal}, dual_trade={dual_trade_enabled}, trade_count={account.multi_trade_count} for account {account_id}")
            
            # Verify the save by re-reading from DB after the save completes
            account.refresh_from_db()
            logger.info(f"✅ VERIFIED after save: account={account_id}, copy_mode={account.copy_mode}, copy_factor={account.copy_factor}")
            
            # IMPORTANT: Commit the transaction NOW before triggering background tasks
            # This ensures the MAM engine can see the updated values immediately
            transaction.on_commit(lambda: trigger_position_update_background(account_id))
            
            # Return success response
            return Response({
                "success": True,
                "message": "Coefficient saved successfully. Existing positions will be updated shortly.",
                "data": {
                    "mode": mode,
                    "factor": str(account.copy_factor),
                    "account_id": account.account_id
                }
            }, status=status.HTTP_200_OK)
            
        except TradingAccount.DoesNotExist:
            return Response(
                {"error": f"Account with ID {account_id} not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    except Exception as e:
        logger.error(f"Error saving coefficient: {str(e)}")
        return Response(
            {"error": "An error occurred while saving the coefficient."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_account_coefficient(request, account_id):
    """Get current coefficient settings for an account"""
    try:
        account = TradingAccount.objects.filter(account_id=str(account_id)).first()
        if not account:
            return Response({'error': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Check if user has permission
        if account.user != request.user and not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        return Response({
            'account_id': account.account_id,
            'copy_mode': account.copy_mode,
            'copy_factor': str(account.copy_factor),
            'dual_trade_enabled': account.dual_trade_enabled,
            'multi_trade_count': account.multi_trade_count if hasattr(account, 'multi_trade_count') else 1
        }, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error in get_account_coefficient: {e}")
        return Response({'error': 'Internal error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def debug_account_coefficient(request, account_id):
    """Debug endpoint: return copy mode/factor and legacy fields for given account_id (admin only)"""
    try:
        account = TradingAccount.objects.filter(account_id=str(account_id)).first()
        if not account:
            return Response({'error': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response({
            'account_id': account.account_id,
            'copy_mode': account.copy_mode,
            'copy_factor': str(account.copy_factor),
            'copy_multiplier_mode': account.copy_multiplier_mode,
            'fixed_copy_multiplier': str(account.fixed_copy_multiplier)
        }, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error in debug_account_coefficient: {e}")
        return Response({'error': 'Internal error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def trigger_position_update_background(account_id):
    """Helper function to trigger position updates in background after transaction commits"""
    # DISABLED: Real-time MAM engine handles position copying automatically
    # Background updates were causing duplicate position creation
    logger.info(f"📋 Position update skipped for account {account_id} - handled by real-time MAM engine")
    return
    
    import threading
    
    def update_positions():
        try:
            from brokerBackend.MPIB_DB import update_existing_positions_for_coefficient_change
            update_existing_positions_for_coefficient_change(int(account_id))
            logger.info(f"✅ Position update triggered for account {account_id}")
        except ImportError:
            logger.warning("MAM engine function not available - positions will update on next trade")
        except Exception as e:
            logger.error(f"❌ Failed to update positions for account {account_id}: {e}")
    
    # Start background thread AFTER transaction commits
    threading.Thread(target=update_positions, daemon=True).start()
    logger.info(f"📤 Background position update scheduled for account {account_id}")
