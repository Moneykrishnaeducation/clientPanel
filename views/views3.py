from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from adminPanel.mt5.services import MT5ManagerActions
import json
from django.utils.timezone import now
from django.conf import settings
from django.core.mail import EmailMessage
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from adminPanel.views.views import generate_password
from adminPanel.models import *
from adminPanel.serializers import *
from clientPanel.serializers import BankDetailsSerializer
from adminPanel.views.views import get_client_ip
from adminPanel.permissions import IsAdminOrManager

class EditPersonalInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        phone = request.data.get("phone_number")
        dob = request.data.get("dob")
        address = request.data.get("address")

        if not any([phone, dob, address]):
            return Response({"error": "At least one field (phone, dob, address) is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Only allow one pending personal info request per user
        if ChangeRequest.objects.filter(user=user, status="PENDING", id_proof__isnull=True, address_proof__isnull=True).exists():
            return Response({"error": "You already have a pending personal info change request."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                change_request = ChangeRequest.objects.create(
                    user=user,
                    requested_data={
                        "phone_number": phone,
                        "dob": dob,
                        "address": address
                    },
                    status="PENDING"
                )
                ActivityLog.objects.create(
                    user=user,
                    activity=f"Requested personal info change: phone={phone}, dob={dob}, address={address}",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="update",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=change_request.id,
                    related_object_type="ChangeRequest"
                )
                return Response({"message": "Personal info change request submitted successfully."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(f"[EditPersonalInfoView] Exception: {str(e)}")
            return Response({"error": f"An error occurred while processing the request: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id=None):
        # If user_id is provided, check permissions
        if user_id is not None:
            # Only allow admins/managers to view other users' details
            from adminPanel.permissions import IsAdminOrManager
            if not IsAdminOrManager().has_permission(request, self):
                # Check if user is viewing their own details
                if str(request.user.user_id) != str(user_id):
                    return Response({"error": "Access denied. You can only view your own details."}, status=status.HTTP_403_FORBIDDEN)
            
            try:
                user = CustomUser.objects.get(user_id=user_id)
            except CustomUser.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            user = request.user
        
        serializer = UserSerializer(user)
        # Only return email and address fields (plus user_id for reference)
        data = serializer.data
        return Response({
            "user_id": data.get("user_id"),
            "email": data.get("email"),
            "address": data.get("address")
        })
     
class BankDetailsRequestStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        
        try:
            bank_details = BankDetails.objects.get(user=request.user)
            bank_details_serializer = BankDetailsSerializer(bank_details)
        except BankDetails.DoesNotExist:
            bank_details_serializer = None

        
        pending_request = BankDetailsRequest.objects.filter(
            user=request.user, status="PENDING"
        ).order_by("-created_at").first()

        if pending_request:
            pending_request_serializer = BankDetailsRequestSerializer(pending_request)
            pending_request_data = pending_request_serializer.data
        else:
            pending_request_data = None

        
        return Response(
            {
                "bank_details": bank_details_serializer.data if bank_details_serializer else None,
                "pending_request": pending_request_data,
            },
            status=status.HTTP_200_OK
        )

class CancelBankDetailsRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, request_id):
        """
        Deletes a pending BankDetailsRequest if it belongs to the current user.
        """
        try:
            
            bank_request = get_object_or_404(BankDetailsRequest, id=request_id, user=request.user, status="PENDING")
            
            
            bank_request.delete()
            return JsonResponse({"success": True, "message": "Bank details request canceled successfully."}, status=200)

        except BankDetailsRequest.DoesNotExist:
            return JsonResponse({"success": False, "error": "Request not found or not eligible for cancellation."}, status=404)
        
class ChangeRequestView(APIView):
    """
    View to handle creating, fetching, and deleting change requests for user updates.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        updated_fields = request.data.get("updated_fields")
        if not updated_fields:
            return Response(
                {"error": "'updated_fields' is required and cannot be empty."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            requested_data = json.loads(updated_fields)
        except json.JSONDecodeError as e:
            return Response(
                {"error": f"Invalid JSON in 'updated_fields': {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        
        id_proof_file = request.FILES.get("id_proof")
        address_proof_file = request.FILES.get("address_proof")
        if not id_proof_file or not address_proof_file:
            return Response(
                {"error": "Both 'id_proof' and 'address_proof' are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            
            with transaction.atomic():
                
                existing_request = ChangeRequest.objects.filter(user=user, status='PENDING').first()

                if existing_request:
                    
                    existing_request.requested_data = requested_data
                    existing_request.id_proof = id_proof_file or existing_request.id_proof
                    existing_request.address_proof = address_proof_file or existing_request.address_proof
                    existing_request.save(update_fields=['requested_data', 'id_proof', 'address_proof'])

                    serializer = ChangeRequestSerializer(existing_request)
                    return Response(
                        {"message": "Pending request updated successfully.", "data": serializer.data},
                        status=status.HTTP_200_OK
                    )

                
                change_request = ChangeRequest.objects.create(
                    user=user,
                    requested_data=requested_data,
                    id_proof=id_proof_file,
                    address_proof=address_proof_file
                )

                serializer = ChangeRequestSerializer(change_request)
                return Response(
                    {"message": "Change request submitted successfully.", "data": serializer.data},
                    status=status.HTTP_201_CREATED
                )
        except Exception as e:
            return Response(
                {"error": "An error occurred while processing the change request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {"error": "An unexpected error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request, *args, **kwargs):
        """
        Get the current user's change request.
        """
        user = request.user
        change_request = ChangeRequest.objects.filter(user=user, status="PENDING").first()

        if not change_request:
            return Response({"message": "No change request found."}, status=status.HTTP_200_OK)

        serializer = ChangeRequestSerializer(change_request)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Delete the current user's change request.
        """
        user = request.user
        change_request = ChangeRequest.objects.filter(user=user, status='PENDING').first()

        if not change_request:
            return Response(
                {"error": "No pending request found to delete."},
                status=status.HTTP_404_NOT_FOUND
            )

        change_request.delete()
        return Response({"message": "Change request deleted successfully."}, status=status.HTTP_200_OK)
    
class CreateMAMAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        
        serializer = MAMAccountSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            pass
            return Response({
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=400)


        validated_data = serializer.validated_data
        
        # Get the default group from TradeGroup (not TradingAccountGroup)
        from adminPanel.models import TradeGroup
        default_group = TradeGroup.objects.filter(is_default=True, is_active=True).first()
        
        if default_group and default_group.name:
            group_name = default_group.name
        else:
            return Response({
                "error": "No default trading group configured. Please configure a default group in the admin panel first."
            }, status=status.HTTP_400_BAD_REQUEST)

        master_password = request.data.get("master_password")
        investor_password = request.data.get("investor_password")
        

        
        # Use a configurable agent value or default
        agent_value = getattr(settings, 'MT5_DEFAULT_AGENT', 626)
        
        mam_id = MT5ManagerActions().add_new_account(
            group_name,
            validated_data['leverage'],
            request.user,
            master_password,
            investor_password,
            agent=agent_value
        )
        

        
        # Validate MT5 account ID is a valid positive integer
        if not mam_id or not isinstance(mam_id, int) or mam_id <= 0:
            error_msg = f"Failed to create account in MT5. Received invalid account ID: {mam_id}"
            print(f"❌ {error_msg}")
            return Response({"error": error_msg}, status=400)

        validated_data['account_id'] = mam_id
        validated_data['group_name'] = group_name
        validated_data['user'] = request.user
        validated_data['account_type'] = 'mam'
        # Ensure the account is enabled by default for MAM accounts
        validated_data['is_enabled'] = True
        validated_data['is_trading_enabled'] = True
        validated_data['status'] = 'active'


        
        mam_account = serializer.create(validated_data)
        
        # Verify the account was created properly
        try:
            mam_trading_account = TradingAccount.objects.get(account_id=mam_id)

        except TradingAccount.DoesNotExist:
            return Response({"error": "Account created in MT5 but failed to save in database"}, status=500)
        if mam_trading_account:
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Created a new MAM account with ID {mam_account.account_id}.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=mam_account.id,
                related_object_type="MAMAccount"
            )
            subject = "Your MAM Manager Account Has Been Created"
            html_message = render_to_string("emails/mam_creation.html", {
                "username": request.user.username,
                "manager_id": mam_account.account_id,
                "master_password": master_password,
                "investor_password": investor_password,
                "mt5_server": 'VTIndex-MT5',
            })
            email = EmailMessage(
                subject=subject,
                body=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[request.user.email],
            )
            email.content_subtype = "html"  
            email.send()
            return Response(
                {"message": "MAM Account created successfully!", "mam_account": MAMAccountSerializer(mam_account).data},
                status=201
            )

class UserMAMAccountsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get all MAM accounts for debugging
        all_mam_accounts = TradingAccount.objects.filter(user=request.user, account_type='mam')
        
        # Filter for valid accounts (with proper account_id and enabled status)
        mam_accounts = all_mam_accounts.filter(
            account_id__isnull=False,
            account_id__gt=0  # Ensure account_id is a positive number
        ).exclude(
            account_id=''  # Exclude empty account_id
        )
        
        for acc in all_mam_accounts:
            pass

        serializer = MAMAccountSerializer(mam_accounts, many=True)
        return Response(serializer.data, status=200)

class MamProfitDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, mam_id):
        try:
            
            try:
                mam_account = TradingAccount.objects.get(
                    user=request.user,
                    account_id=mam_id,
                    account_type="mam"
                )
            except TradingAccount.DoesNotExist:
                return Response(
                    {"error": "MAM account not found or you do not have access."},
                    status=status.HTTP_404_NOT_FOUND
                )

            
            investor_accounts = mam_account.investments.filter(account_type="mam_investment")

            
            investor_profits = []
            for investor in investor_accounts:
                
                investor_profit = 0  
                investor_profits.append({
                    "investor_account_id": investor.account_id,
                    "investor_account_name": investor.account_name,
                    "profit": investor_profit
                })

            
            mam_profit = 0  

            
            profit_data = {
                "mam_account_id": mam_account.account_id,
                "mam_account_name": mam_account.account_name,
                "mam_profit": mam_profit,
                "investor_profits": investor_profits,
            }

            return Response(profit_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ToggleMamAlgoView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            mam_id = request.data.get("mam_id")
            enable_algo = request.data.get("enable_algo")

            if mam_id is None or enable_algo is None:
                return Response(
                    {"error": "mam_id and enable_algo are required fields."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                mam_account = TradingAccount.objects.get(
                    user=request.user,
                    account_id=mam_id,
                    account_type="mam"
                )
            except TradingAccount.DoesNotExist:
                return Response(
                    {"error": "MAM account not found or access denied."},
                    status=status.HTTP_404_NOT_FOUND
                )

            if MT5ManagerActions().toggle_algo(int(mam_account.account_id), action="enable" if enable_algo else "disable"):
                mam_account.is_algo_enabled = enable_algo
                mam_account.save()
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Algorithmic trading {'enabled' if enable_algo else 'disabled'} for MAM account with ID {mam_account.account_id}.",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="update",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=mam_account.id,
                    related_object_type="MAMAccount"
                )

                return Response(
                    {
                        "message": f"Algorithmic trading {'enabled' if enable_algo else 'disabled'} successfully.",
                        "mam_id": mam_id,
                        "is_algo_enabled": mam_account.is_algo_enabled,
                    },
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        
class ToggleMamTradingStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            mam_id = request.data.get("mam_id")
            enable_trading = request.data.get("enable_trading")
            # Accept both string and int for enable_trading
            if isinstance(enable_trading, str):
                if enable_trading.isdigit():
                    enable_trading = int(enable_trading)
                else:
                    enable_trading = 1 if enable_trading.lower() in ["true", "yes", "enable"] else 0
            elif isinstance(enable_trading, bool):
                enable_trading = int(enable_trading)
            # Validate required fields
            if mam_id is None or enable_trading is None:
                return Response(
                    {"error": "mam_id and enable_trading are required fields."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                mam_account = TradingAccount.objects.get(
                    user=request.user,
                    account_id=mam_id,
                    account_type="mam"
                )
            except TradingAccount.DoesNotExist:
                return Response(
                    {"error": "MAM account not found or access denied."},
                    status=status.HTTP_404_NOT_FOUND
                )
            # Actually toggle trading status
            action = "enable" if enable_trading else "disable"
            if MT5ManagerActions().toggle_account_status(login_id=int(mam_id), action=action):
                mam_account.is_enabled = bool(enable_trading)
                mam_account.save()
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Trading {'enabled' if enable_trading else 'disabled'} for MAM account with ID {mam_account.account_id}.",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="update",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=mam_account.id,
                    related_object_type="MAMAccount"
                )
                return Response(
                    {
                        "message": f"Trading {'enabled' if enable_trading else 'disabled'} successfully.",
                        "mam_id": mam_id,
                        "is_trading_enabled": mam_account.is_enabled,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"error": "Failed to update trading status in MT5."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
         
class MamInvestorsView(APIView):
    """
    API view to get all investors associated with a specific MAM account.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, mam_id):
        try:
            
            try:
                mam_account = TradingAccount.objects.get(
                    user=request.user,
                    account_id=mam_id,
                    account_type="mam"
                )
            except TradingAccount.DoesNotExist:
                return Response(
                    {"error": "MAM account not found or access denied."},
                    status=status.HTTP_404_NOT_FOUND
                )

            
            investor_accounts = TradingAccount.objects.filter(
                mam_master_account=mam_account,
                account_type="mam_investment"
            )

            if not investor_accounts.exists():
                return Response(
                    {"message": "No investors found for this MAM account."},
                    status=status.HTTP_200_OK
                )

            
            serializer = TradingAccountSerializer(investor_accounts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
def calculate_growth_percentage(mt5action, account_id):
    """
    Calculate the growth percentage for a MAM account.
    Growth is calculated as: ((current_balance - total_deposits + total_withdrawals) / total_deposits) * 100
    """
    try:
        current_balance = float(mt5action.get_balance(int(account_id)))
        total_deposits = float(mt5action.total_account_deposits(int(account_id)))
        total_withdrawals = float(mt5action.total_account_withdrawls(int(account_id)))

        if total_deposits > 0:
            net_invested = total_deposits - total_withdrawals
            if net_invested > 0:
                growth = ((current_balance - net_invested) / net_invested) * 100
                return f"{growth:.2f}%"
            else:
                return "0.00%"
        else:
            return "0.00%"
    except Exception as e:
        print(f"Error calculating growth for account {account_id}: {str(e)}")
        return "0.00%"


        
class AvailableMAMManagersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Allow users to create multiple investment accounts with same manager
            # Remove exclusion of subscribed managers to enable multiple investor accounts
            mam_accounts = TradingAccount.objects.filter(
                account_type="mam",
                is_enabled=True,
            ).exclude(user=request.user)  # Only exclude user's own MAM manager accounts

            
            mam_data = []
            mt5action = MT5ManagerActions()
            for mam_account in mam_accounts:
                account_data = {
                    "accountId": mam_account.account_id,  # Primary field expected by frontend
                    "id": mam_account.account_id,  # Fallback field expected by frontend
                    "mam_account_id": mam_account.account_id,  # Legacy field
                    "name": mam_account.account_name,
                    "leverage": mam_account.leverage if hasattr(mam_account, 'leverage') else None,
                    "package_leverage": mam_account.leverage if hasattr(mam_account, 'leverage') else None,
                    "manager_name": f"{mam_account.user.first_name} {mam_account.user.last_name}",
                    "growth_percentage": "",  
                    "profitShare": f"{mam_account.profit_sharing_percentage}%",  # Frontend expects profitShare
                    "profit_sharing": f"{mam_account.profit_sharing_percentage}%",  # Fallback
                    "profit_sharing_percentage": mam_account.profit_sharing_percentage,  # Legacy
                    "riskLevel": mam_account.risk_level or "medium",  # Frontend expects riskLevel
                    "risk_level": mam_account.risk_level or "medium",  # Fallback
                    "status": "enabled" if mam_account.is_enabled else "disabled",
                    "total_profit": round(float(mt5action.total_account_profit(int(mam_account.account_id))),2),
                    "total_deposits": round(float(mt5action.total_account_deposits(int(mam_account.account_id))),2),
                    "total_withdrawals": round(float(mt5action.total_account_withdrawls(int(mam_account.account_id))),2),
                    "accountAge": f"{(now() - mam_account.created_at).days} days",  # Frontend expects accountAge
                    "account_age": f"{(now() - mam_account.created_at).days} days",  # Fallback
                    "account_age_in_days": (now() - mam_account.created_at).days,  # Legacy
                    "balance": f"${round(float(mt5action.get_balance(int(mam_account.account_id))),2)}",  # Frontend expects balance
                    "current_balance": round(float(mt5action.get_balance(int(mam_account.account_id))),2),  # Legacy
                    "equity": f"${round(float(mt5action.get_equity(int(mam_account.account_id))),2)}",  # Frontend expects equity
                    "current_equity": round(float(mt5action.get_equity(int(mam_account.account_id))),2),  # Legacy
                     "growth": calculate_growth_percentage(mt5action, mam_account.account_id),  # Frontend expects growth
              
                }
                mam_data.append(account_data)
                
            del mt5action
            return Response(mam_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CreateMAMInvestmentAccountView(APIView):
    """
    API View to create a MAM Investment Account directly.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        def send_investor_account_email(investor, mam_investment_account, investor_password):
            """
            Sends an email to the investor with their investment account details.
            """
            subject = "Your MAM Investment Account Has Been Created"
            html_message = render_to_string("emails/investor_account_details.html", {
                "investor_name": investor.username,
                "account_id": mam_investment_account.account_id,
                "investor_password": investor_password,
                "mt5_server": "VTIndex-MT5",  
            })
            email = EmailMessage(
                subject=subject,
                body=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[investor.email],
            )
            email.content_subtype = "html"  
            email.send()

        def send_new_investor_notification(mam_manager, investor, mam_investment_account):
            """
            Sends an email to the MAM manager notifying them about a new investor copying their account.
            """
            subject = "New Investor Copying Your MAM Account"
            html_message = render_to_string("emails/new_investor.html", {
                "mam_manager_name": mam_manager.username,
                "investor_name": investor.username,
                "investor_email": investor.email,
                "investor_account_id": mam_investment_account.account_id,
            })
            email = EmailMessage(
                subject=subject,
                body=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[mam_manager.email],
            )
            email.content_subtype = "html"  
            email.send()
        try:
            user = request.user
            # Support both new frontend parameters and legacy parameters
            mam_master_id = request.data.get('manager_id') or request.data.get('mam_account')
            master_password = request.data.get('master_password')
            investor_password = request.data.get('password') or request.data.get('investor_password')

            # Get optional user details for MT5 account creation
            user_name = request.data.get('user_name', '')
            user_email = request.data.get('user_email', user.email)
            user_phone = request.data.get('user_phone', '')
            
            if not mam_master_id:
                return Response(
                    {"error": "Manager ID is required (manager_id or mam_account)."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                mam_master_account = TradingAccount.objects.get(
                    account_id=mam_master_id, account_type='mam'
                )
            except TradingAccount.DoesNotExist:
                return Response(
                    {"error": "Invalid MAM master account ID."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate password is provided
            if not investor_password:
                return Response({
                    "error": "Password is required. Please enter a password for your investment account."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Allow multiple investment accounts per user for the same manager
            # Removed the unique constraint check to enable multiple investor accounts under same manager
            mt5action = MT5ManagerActions()
            groupName = mt5action.get_group_of(int(mam_master_id))
            
            # Do NOT reuse the investor password as the master password.
            # If a master password was provided by the caller use it, otherwise generate a secure random one.
            # This ensures investor accounts do not receive trading privileges.
            if not master_password:
                master_password = generate_password()

            agent_account = int(mam_master_account.account_id)
            mam_inv_id = mt5action.add_new_account(groupName, int(mam_master_account.leverage), request.user, master_password, investor_password, int(agent_account))
            if mam_inv_id:
                # Create a unique account name for multiple investments with same manager
                existing_accounts_count = TradingAccount.objects.filter(
                    user=user,
                    mam_master_account=mam_master_account,
                    account_type='mam_investment'
                ).count()
                
                if existing_accounts_count > 0:
                    account_name = f"{mam_master_account.account_name} - Investment #{existing_accounts_count + 1}"
                else:
                    account_name = f"{mam_master_account.account_name} - Investment"
                
                mam_investment_account = TradingAccount.objects.create(
                    user=user,
                    account_type='mam_investment',
                    mam_master_account=mam_master_account,
                    account_id = mam_inv_id,
                    account_name=account_name,
                    leverage=mam_master_account.leverage,
                    group_name=mam_master_account.group_name,
                    risk_level=mam_master_account.risk_level,
                )
                serializer = TradingAccountSerializer(mam_investment_account)
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Created a new MAM Investment Account with ID {mam_investment_account.account_id} linked to MAM Master Account ID {mam_master_account.account_id}. (Account #{existing_accounts_count + 1})",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="create",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=mam_investment_account.id,
                    related_object_type="MAMInvestmentAccount"
                )
                send_new_investor_notification(
                                    mam_manager=mam_master_account.user,
                                    investor=user,
                                    mam_investment_account=mam_investment_account
                                )
                send_investor_account_email(
                    investor=user,
                    mam_investment_account=mam_investment_account,
                    investor_password=investor_password
                )

                # Return success response with account details.
                # Do NOT include or leak the master password. Investor clients should never receive the master password.
                return Response({
                    "success": True,
                    "message": "MAM investment account created successfully",
                    "account_id": mam_inv_id,
                    "investor_password": "****" + investor_password[-4:],  # Only send last 4 chars for security
                    "mam_master_id": mam_master_id,
                    **serializer.data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response(
                    {"error": "Failed to create MT5 investment account. Please try again."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserInvestmentsView(APIView):
    """
    API View to fetch user investment accounts linked to MAM managers.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            investments = TradingAccount.objects.filter(
                user=user,
                account_type='mam_investment'
            ).select_related('mam_master_account', 'mam_master_account__user')

            mt5action = MT5ManagerActions()
            data = []
            
            for investment in investments:
                # Get real-time balance and equity from MT5
                current_balance = mt5action.get_balance(int(investment.account_id))
                current_equity = mt5action.get_equity(int(investment.account_id))
                
                investment_data = {
                    # Primary fields expected by frontend
                    "accountId": investment.account_id,
                    "id": investment.account_id,  # Fallback
                    "manager_name": f"{investment.mam_master_account.user.first_name} {investment.mam_master_account.user.last_name}",
                    "name": investment.account_name,  # Fallback
                    "balance": f"${round(float(current_balance), 2)}" if current_balance else "$0.00",
                    "equity": f"${round(float(current_equity), 2)}" if current_equity else "$0.00",
                    "profitShare": f"{investment.mam_master_account.profit_sharing_percentage}%",
                    "profit_sharing": f"{investment.mam_master_account.profit_sharing_percentage}%",  # Fallback
                    "leverage": investment.leverage,
                    "status": "Copying" if investment.is_enabled else "Paused",
                    
                    # Additional useful fields
                    "master_account_id": investment.mam_master_account.account_id,
                    "investment_id": investment.id,
                    "created_at": investment.created_at.isoformat() if investment.created_at else None,
                    "risk_level": investment.risk_level or investment.mam_master_account.risk_level,
                    "group_name": investment.group_name,
                    
                    # Legacy fields for compatibility
                    "mam_account_name": investment.mam_master_account.account_name,
                    "trading_account_id": investment.account_id,
                    "amount_invested": float(current_balance) if current_balance else 0.0,
                    "profit": float(current_equity - current_balance) if (current_equity and current_balance) else 0.0,
                }
                data.append(investment_data)
            
            del mt5action
            return Response(data, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=500)

class PauseCopyingView(APIView):
    """
    API to pause copying for an investment account.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        mam_id = request.data.get('mam_id')
        if not mam_id:
            return Response({"error": "MAM account ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            account = TradingAccount.objects.get(account_id=mam_id, user=request.user, account_type='mam_investment')
        except TradingAccount.DoesNotExist:
            return Response({"error": "Invalid MAM account ID or permission denied."}, status=status.HTTP_404_NOT_FOUND)

        
        if not account.manager_allow_copy:
            return Response({"error": "Manager does not allow copying for this account."}, status=status.HTTP_403_FORBIDDEN)

        if MT5ManagerActions().pause_mam_copy(int(account.account_id)):
            account.investor_allow_copy = False
            account.save()
            
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Paused copying for MAM Investment Account with ID {account.account_id}.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="update",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=account.id,
                related_object_type="MAMInvestmentAccount"
            )

            return Response({"message": "Copying paused successfully."}, status=status.HTTP_200_OK)

class StartCopyingView(APIView):
    """
    API to start copying for an investment account.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        mam_id = request.data.get('mam_id')
        if not mam_id:
            return Response({"error": "MAM account ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            account = TradingAccount.objects.get(account_id=mam_id, user=request.user, account_type='mam_investment')
        except TradingAccount.DoesNotExist:
            return Response({"error": "Invalid MAM account ID or permission denied."}, status=status.HTTP_404_NOT_FOUND)
        if not account.manager_allow_copy:
            return Response({"error": "Manager does not allow copying for this account."}, status=status.HTTP_403_FORBIDDEN)
        mam_manager_id = account.mam_master_account.account_id
        result = MT5ManagerActions().start_mam_copy(int(account.account_id), int(mam_manager_id))
        if result:
            account.investor_allow_copy = True
            account.save()
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Started copying for MAM Investment Account with ID {account.account_id}.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="update",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=account.id,
                related_object_type="MAMInvestmentAccount"
            )
            return Response({"message": "Copying started successfully."}, status=status.HTTP_200_OK)
        else:
            print(f"[StartCopyingView] Failed to start copying for account {account.account_id}")
            return Response({"error": "Failed to start copying in MT5."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)