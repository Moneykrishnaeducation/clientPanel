
# ...existing imports...

# Place TicketsView after all imports




# All imports must be at the very top of the file
from adminPanel.mt5.services import MT5ManagerActions
from django.utils.timezone import now
from django.conf import settings
from django.core.mail import EmailMessage
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from adminPanel.models import *
from adminPanel.serializers import *
from adminPanel.views.views import get_client_ip, generate_password

# Now define TicketsView after all imports
class TicketsView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request):
        try:
            user_tickets = Ticket.objects.filter(created_by=request.user).order_by("-created_at")
            grouped = {"open": [], "closed": [], "pending": []}
            for ticket in user_tickets:
                status_key = str(ticket.status).lower()
                if status_key in grouped:
                    grouped[status_key].append(TicketSerializer(ticket).data)
                else:
                    # If status is not one of the expected, put in 'pending' as fallback
                    grouped["pending"].append(TicketSerializer(ticket).data)
            return Response(grouped, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "Failed to fetch tickets.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def post(self, request):
        try:
            data = request.data
            # Collect uploaded files from common field names; fall back to any uploaded files
            if "documents" in request.FILES:
                files = request.FILES.getlist("documents")
            elif "documents[]" in request.FILES:
                files = request.FILES.getlist("documents[]")
            else:
                # fallback: include all uploaded files
                files = list(request.FILES.values())
            # Log for debugging
            try:
                print(f"CreateTicketView: received {len(files)} files")
            except Exception:
                pass
            ticket_data = {
                "subject": data.get("subject"),
                "description": data.get("description"),
            }
            serializer = TicketSerializer(data=ticket_data)
            if serializer.is_valid():
                with transaction.atomic():
                    ticket = serializer.save(created_by=request.user)
                    # Save uploaded files as Message entries attached to the ticket
                    for f in files:
                        Message.objects.create(ticket=ticket, sender=request.user, file=f)
                # Return full ticket data including messages (with file paths)
                ticket_resp = TicketWithMessagesSerializer(ticket, context={'request': request}).data
                return Response({"message": "Ticket created successfully!", "ticket": ticket_resp}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(
                {"error": "Failed to create ticket. Please try again.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# AdminTicketsView: show 'open' tickets from clients/managers as 'pending' for admin panel
from rest_framework.permissions import IsAdminUser

class AdminTicketsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            tickets = Ticket.objects.all().order_by("-created_at")
            ticket_list = []
            for ticket in tickets:
                ticket_data = TicketSerializer(ticket).data
                # Adjust this line to match your user model's role field
                user_role = getattr(ticket.created_by, 'role', None)
                if ticket.status == 'open' and user_role in ['client', 'manager']:
                    ticket_data['status'] = 'pending'
                ticket_list.append(ticket_data)
            grouped = {'open': [], 'closed': [], 'pending': []}
            for t in ticket_list:
                status_key = t['status'].lower()
                if status_key in grouped:
                    grouped[status_key].append(t)
            return Response(grouped, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "Failed to fetch tickets.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
import json
from adminPanel.mt5.services import MT5ManagerActions
from django.utils.timezone import now
from django.conf import settings
from django.core.mail import EmailMessage
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from adminPanel.models import *
from adminPanel.serializers import *
from adminPanel.views.views import get_client_ip, generate_password


class ToggleAlgoView(APIView):
    def post(self, request, mam_id):
        # Verify account ownership - never trust client-provided IDs
        account = get_object_or_404(TradingAccount, account_id=mam_id, user=request.user)
        if account.is_trading_enabled:
            action = "disable"
        else:
            action = "enable"
        
        if MT5ManagerActions().toggle_algo(int(mam_id), action):
            account.is_trading_enabled = not account.is_trading_enabled
            account.save()
            status_message = "enabled" if account.is_trading_enabled else "disabled"
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Algo trading has been {'enabled' if account.is_trading_enabled else 'disabled'} for account {account.account_id}.",
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
                {"message": f"Algo trading has been {status_message} successfully."},
                status=status.HTTP_200_OK,
            )

class CreateDemoAccountView(APIView):
    def post(self, request):
        user = request.user
        # Set defaults for optional fields
        balance = request.data.get("balance", "10000")
        leverage = request.data.get("leverage", "500")
        master_password = request.data.get("masterPassword") or generate_password()
        investor_password = request.data.get("investorPassword") or generate_password()

        # Validate inputs
        try:
            balance = Decimal(balance)
            if leverage not in ["1", "2", "5", "10", "20", "50", "100", "200", "500"]:
                raise ValueError("Invalid leverage value.")
        except (ValueError, Decimal.InvalidOperation):
            return Response(
                {"error": "Invalid balance or leverage value."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get demo account group with fallback
        try:
            trading_group = TradingAccountGroup.objects.order_by('-created_at').first()
            if trading_group and trading_group.demo_account_group:
                group_name = trading_group.demo_account_group
            else:
                # Fallback to a default demo group name
                group_name = "demo"
        except Exception:
            # Fallback if no TradingAccountGroup exists
            group_name = "demo"
            
        # Create demo account with better error handling
        try:
            mt5action = MT5ManagerActions()
            # Use the newer create_account method with proper error handling
            account_result = mt5action.create_account(
                name=f"{user.first_name} {user.last_name}".strip(),
                email=user.email,
                phone=user.phone_number,
                group=group_name,
                leverage=int(leverage),
                password=master_password,
                investor_password=investor_password,
                account_type='demo'
            )
            
            if account_result and account_result.get('login'):
                demo_id = account_result.get('login')
                # Try to deposit funds, but don't fail if it doesn't work
                deposit_success = True
                try:
                    deposit_success = mt5action.deposit_funds(demo_id, round(float(balance), 2), "Demo Deposit")
                except Exception as deposit_error:
                    print(f"Demo deposit failed: {deposit_error}")
                    # Continue with account creation even if deposit fails
                    deposit_success = False

                demo_account = DemoAccount.objects.create(
                    user=user,
                    account_id=demo_id,
                    balance=balance if deposit_success else Decimal("0.00"),
                    leverage=leverage,
                    account_name=f"{user.username} - Demo",
                )
                demo_account.save()

                # Send demo account creation email
                try:
                    from adminPanel.EmailSender import EmailSender
                    email_sent = EmailSender.send_demo_account_creation(
                        user_email=user.email,
                        username=user.username,
                        account_id=demo_id,
                        master_password=master_password,
                        investor_password=investor_password,
                        balance=balance,
                        leverage=leverage
                    )
                except Exception as e:
                    print(f"Error sending demo account creation email to {user.email}: {str(e)}")
                    # Don't fail the entire operation if email fails

                ActivityLog.objects.create(
                    user=user,
                    activity=f"Created demo account with ID {demo_account.account_id}.",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="create",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=demo_account.id,
                    related_object_type="DemoAccount"
                )

                response_data = {
                    "message": "Demo account created successfully.",
                    "account_id": demo_account.account_id,
                    "balance": str(demo_account.balance),
                    "leverage": demo_account.leverage
                }
                
                if not deposit_success:
                    response_data["warning"] = "Account created but initial deposit failed. MT5 server may be unavailable."

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                # Account creation failed
                return Response(
                    {"error": "Failed to create demo account. MT5 server may be unavailable or permissions insufficient."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            print(f"Demo account creation error: {e}")
            return Response(
                {"error": f"Failed to create demo account: {str(e)}. Please try again or contact support."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class ResetDemoBalanceView(APIView):
    def post(self, request, account_id):
        account = get_object_or_404(DemoAccount, account_id=account_id, user=request.user)
        balance = request.data.get("balance")

        
        try:
            balance = float(balance)
            if balance <= 0:
                raise ValueError("Balance must be greater than zero.")
        except (TypeError, ValueError):
            return Response(
                {"error": "Invalid balance value. Must be a positive number."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        mt5action = MT5ManagerActions()
        cur_balance = mt5action.get_balance(int(account_id))
        checker = float(balance) - cur_balance
        if checker > 0:
            tr = mt5action.deposit_funds(int(account_id), checker, "Demo Reset")
        if checker < 0:
            tr = mt5action.withdraw_funds(int(account_id), -checker,"Demo Reset")
        if tr:
            account.balance = mt5action.get_balance(int(account_id))
            account.save()

            return Response({"message": "Balance updated successfully.", "balance": account.balance},status=status.HTTP_200_OK,)
        else:
            return Response({"error": "Balance updation failed.",},status=status.HTTP_500_INTERNAL_SERVER_ERROR,)

class ChangeDemoLeverageView(APIView):
    def post(self, request, account_id):
        
        account = get_object_or_404(DemoAccount, account_id=account_id, user=request.user)
        leverage = request.data.get("leverage")

        
        valid_leverage_options = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000]
        try:
            leverage = int(leverage)
            if leverage not in valid_leverage_options:
                raise ValueError("Invalid leverage value.")
        except (TypeError, ValueError):
            return Response(
                {"error": f"Invalid leverage value. Must be one of {valid_leverage_options}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        
        account.leverage = str(leverage)
        account.save()

        return Response(
            {"message": "Leverage updated successfully.", "leverage": account.leverage},
            status=status.HTTP_200_OK,
        )

class CreateTicketView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        try:
            data = request.data
            files = request.FILES.getlist("documents")

            
            ticket_data = {
                "subject": data.get("subject"),
                "description": data.get("description"),
            }
            serializer = TicketSerializer(data=ticket_data)
            if serializer.is_valid():
                with transaction.atomic():
                    ticket = serializer.save(created_by=request.user)

                    
                    for file in files:
                        Message.objects.create(
                            ticket=ticket,
                            sender=request.user,
                            file=file,
                        )
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Created a new support ticket with subject '{data.get('subject')}'.",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="create",
                    activity_category="client",
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=now(),
                    related_object_id=ticket.id,
                    related_object_type="Ticket"
                )

                return Response(
                    {"message": "Ticket created successfully!", "ticket": serializer.data},
                    status=status.HTTP_201_CREATED,
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(
                {"error": "Failed to create ticket. Please try again.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class UserTicketsView(APIView):
    """
    View for fetching tickets created by the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            
            user_tickets = Ticket.objects.filter(created_by=request.user).order_by("-created_at")
            serializer = TicketSerializer(user_tickets, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "Failed to fetch tickets.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class TicketMessagesView(APIView):
    """
    Fetch messages for a specific ticket.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, ticket_id):
        try:
            # Allow admin to change any ticket, user can only change their own
            if hasattr(request.user, 'is_staff') and (request.user.is_staff or getattr(request.user, 'is_superuser', False)):
                ticket = Ticket.objects.get(id=ticket_id)
            else:
                ticket = Ticket.objects.get(id=ticket_id, created_by=request.user)
            new_status = request.data.get("status")
            if new_status not in [choice[0] for choice in Ticket.STATUS_CHOICES]:
                return Response({"error": "Invalid status."}, status=status.HTTP_400_BAD_REQUEST)
            ticket.status = new_status
            ticket.save()
            # Optionally log activity here
            return Response({"message": "Status updated."}, status=status.HTTP_200_OK)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response(
                {"error": "Failed to fetch messages.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class SendMessageView(APIView):
    """
    Send a new message for a specific ticket.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request, ticket_id):
        try:
            ticket = Ticket.objects.get(id=ticket_id)
            data = request.data
            data["ticket"] = ticket.id
            data["sender"] = request.user.id

            serializer = MessageSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(
                {"error": "Failed to send the message.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TicketDetailClientView(APIView):
    """
    Client-facing ticket detail view (includes messages/attachments).
    Returns 403 if the authenticated user does not own the ticket (unless staff).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, ticket_id):
        try:
            # Staff can view any ticket; regular users can view only their own
            if hasattr(request.user, 'is_staff') and (request.user.is_staff or getattr(request.user, 'is_superuser', False)):
                ticket = Ticket.objects.get(id=ticket_id)
            else:
                ticket = Ticket.objects.get(id=ticket_id, created_by=request.user)

            serializer = TicketWithMessagesSerializer(ticket, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ChangeTicketStatusView(APIView):
    """
    Change the status of a specific ticket.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, ticket_id):
        try:
            ticket = Ticket.objects.get(id=ticket_id, created_by=request.user)
            new_status = request.data.get("status")

            if new_status not in [choice[0] for choice in Ticket.STATUS_CHOICES]:
                return Response(
                    {"error": "Invalid status."}, status=status.HTTP_400_BAD_REQUEST
                )

            ticket.status = new_status
            ticket.save()
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Changed status of ticket #{ticket_id} to '{new_status}'.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="update",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=ticket.id,
                related_object_type="Ticket"
            )

            return Response({"success": "Status updated successfully."}, status=status.HTTP_200_OK)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(
                {"error": "Failed to change status.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class GetMyDetailsView(APIView):
    """
    Retrieve details of the currently authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            user_details = {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_staff": user.is_staff,
                "date_joined": user.date_joined,
            }
            return Response(user_details, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Failed to fetch user details.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PropTradingRequestView(APIView):
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Get all prop trading requests for the authenticated user.
        """
        user = request.user
        requests = PropTradingRequest.objects.filter(user=user).order_by("-created_at")
        serializer = PropTradingRequestSerializer(requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Create a new PropTradingRequest for the authenticated user.
        Handles both form-data and JSON requests.
        """
        user = request.user
        
        # Handle different content types
        if hasattr(request, 'content_type') and 'application/json' in request.content_type:
            # For JSON requests, just create a basic request without file
            data = request.data
            proof_of_payment = None
        else:
            # For form-data requests, handle file upload
            data = request.data
            proof_of_payment = request.FILES.get("proof_of_payment")
        
        # Get package
        try:
            package_id = data.get("package_id")
            if not package_id:
                return Response({"error": "Package ID is required."}, status=status.HTTP_400_BAD_REQUEST)
            package = Package.objects.get(id=package_id)
        except Package.DoesNotExist:
            return Response({"error": "Invalid package ID."}, status=status.HTTP_400_BAD_REQUEST)

        # Create prop request
        prop_request = PropTradingRequest.objects.create(
            user=user,
            package=package,
            proof_of_payment=proof_of_payment,
        )

        
        serializer = PropTradingRequestSerializer(prop_request)
        ActivityLog.objects.create(
            user=request.user,
            activity=f"Created a new proprietary trading request for package '{package.name}'.",
            ip_address=get_client_ip(request),
            endpoint=request.path,
            activity_type="create",
            activity_category="client",
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            timestamp=now(),
            related_object_id=prop_request.id,
            related_object_type="PropTradingRequest"
        )

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class MyRequestsView(APIView):
    """
    API view to fetch prop trading requests for the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Retrieve all prop trading requests submitted by the authenticated user.
        """
        user = request.user
        requests = PropTradingRequest.objects.filter(user=user).order_by("-created_at")
        serializer = PropTradingRequestSerializer(requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CancelRequestView(APIView):
    """
    API view to delete a pending PropTradingRequest.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            
            prop_request = PropTradingRequest.objects.get(pk=pk, user=request.user)

            
            if prop_request.status != "pending":
                return Response(
                    {"error": "Only pending requests can be deleted."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            prop_request.delete()
            ActivityLog.objects.create(
                user=request.user,
                activity=f"Canceled proprietary trading request with ID {prop_request.id}.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="delete",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=prop_request.id,
                related_object_type="PropTradingRequest"
            )

            return Response({"success": "Request deleted successfully."}, status=status.HTTP_200_OK)

        except PropTradingRequest.DoesNotExist:
            return Response(
                {"error": "Request not found or not authorized."},
                status=status.HTTP_404_NOT_FOUND,
            )
            
class  CreateTradingAccountView(APIView):
    """
    API View to handle the creation of a new trading account with master and investor passwords.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        account_name = request.data.get('accountName', '')
        leverage = str(request.data.get('leverage', '100'))
        group = request.data.get('group', '')  # Get the selected group
        # Clean up leverage value
        leverage = leverage.rstrip('x') if isinstance(leverage, str) else str(leverage)
        master_password = request.data.get('masterPassword')  # This will be the main/master password
        investor_password = request.data.get('investorPassword')  # This will be the investor password
        account_type = request.data.get('accountType', 'real')  # Default to real account
        
        try:
            # Validate that a group was selected
            if not group:
                return Response({
                    'error': 'Group selection required',
                    'details': 'Please select a trading group'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate the group exists and is active
            from adminPanel.models import TradeGroup
            try:
                trade_group = TradeGroup.objects.get(id=group, is_active=True)
                group_name = trade_group.name
            except TradeGroup.DoesNotExist:
                return Response({
                    'error': 'Invalid group',
                    'details': 'Selected trading group is not available'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Initialize MT5 manager with detailed logging
            mt5_service = MT5ManagerActions()
            
            if not mt5_service.manager:
                logger.error("MT5 connection is not available")
                return Response({
                    'error': 'MT5 connection is not available',
                    'details': 'Could not establish connection to MT5 server'
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

            # Create the account in MT5 first
            # First validate passwords
            if not master_password or not investor_password:
                return Response({
                    'error': 'Missing passwords',
                    'details': 'Both master and investor passwords are required'
                }, status=status.HTTP_400_BAD_REQUEST)

            if len(master_password) < 8 or len(investor_password) < 8:
                return Response({
                    'error': 'Invalid passwords',
                    'details': 'Passwords must be at least 8 characters long'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create account in MT5
            mt5_result = mt5_service.create_account(
                name=account_name or f"{user.first_name} {user.last_name}".strip() or user.email,
                email=user.email,
                phone=getattr(user, 'phone', ''),
                leverage=int(leverage),
                password=master_password,
                investor_password=investor_password,
                account_type=account_type,
                group=group_name  # Pass the group name to MT5
            )
            
            if not mt5_result:
                logger.error("MT5 account creation failed")
                return Response({
                    'error': 'Failed to create MT5 account',
                    'details': 'MT5 server rejected the account creation request'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if not isinstance(mt5_result, dict) or 'login' not in mt5_result:
                logger.error("MT5 account creation response invalid")
                return Response({
                    'error': 'Invalid MT5 response',
                    'details': 'MT5 server returned an invalid response'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            mt5_login = str(mt5_result['login'])
            mt5_group = mt5_result['group']
            logger.info(f"MT5 account created successfully with ID: {mt5_login}")
            
            try:
                # Create appropriate account record based on account type
                if account_type.lower() == 'demo':
                    # Create DemoAccount record for demo accounts
                    account = DemoAccount.objects.create(
                        user=user,
                        account_id=mt5_login,  # Use MT5 login as account_id
                        account_name=account_name or f"Demo Account {mt5_login}",
                        leverage=str(leverage),
                        balance=Decimal(request.data.get('balance', '10000.00'))  # Use provided balance or default
                    )
                    account_record_type = 'demo'
                else:
                    # Create TradingAccount record for real/live accounts
                    account = TradingAccount.objects.create(
                        user=user,
                        account_id=mt5_login,  # Use MT5 login as account_id
                        account_name=account_name or f"Trading Account {mt5_login}",
                        account_type='standard',  # Default to standard account
                        leverage=int(leverage),
                        balance=Decimal('0.00'),  # Start with 0 balance
                        equity=Decimal('0.00'),  # Start with 0 equity
                        group_name=group_name  # Store the group name
                    )
                    account_record_type = 'real'
                
                logger.info(f"Created {account_record_type} DB record for MT5 account {mt5_login}")

                # Send email with account credentials to the user
                try:
                    from adminPanel.EmailSender import EmailSender
                    username = f"{user.first_name} {user.last_name}".strip() or user.email.split('@')[0]
                    
                    # Get the MT5 server name from settings
                    try:
                        from adminPanel.mt5.models import ServerSetting
                        latest_setting = ServerSetting.objects.latest('created_at')
                        mt5_server_name = latest_setting.server_name_client if latest_setting else 'VTIndex-MT5'
                    except Exception:
                        mt5_server_name = 'VTIndex-MT5'  # Fallback
                    
                    email_sent = EmailSender.send_new_account_creation(
                        user_email=user.email,
                        username=username,
                        account_id=account.account_id,
                        master_password=mt5_result['master_password'],
                        investor_password=mt5_result['investor_password'],
                        mt5_server_name=mt5_server_name
                    )
                    
                    if email_sent:
                        logger.info(f"Account creation email sent successfully to {user.email}")
                    else:
                        logger.warning(f"Failed to send account creation email to {user.email}")
                        
                except Exception as email_error:
                    logger.error(f"Error sending account creation email to {user.email}: {str(email_error)}")
                    # Don't fail the account creation if email fails

                # Return success response with account details
                return Response({
                    'success': True,
                    'account': {
                        'account_id': account.account_id,
                        'account_name': account.account_name,
                        'holder_name': f"{user.first_name} {user.last_name}".strip() or user.email,
                        'email': user.email,
                        'phone': getattr(user, 'phone', ''),
                        'leverage': str(account.leverage),
                        'balance': float(account.balance),
                        'group_name': group_name,
                        'account_type': account_record_type,
                        'master_password': mt5_result['master_password'],
                        'investor_password': mt5_result['investor_password']
                    },
                    'message': f'{account_record_type.title()} account created successfully'
                }, status=status.HTTP_201_CREATED)

            except Exception as e:
                logger.error(f"Failed to create DB record for MT5 account {mt5_login}: {str(e)}")
                
                # Try to delete the MT5 account since DB creation failed
                try:
                    logger.info(f"Attempting to delete MT5 account: {mt5_login}")
                    if mt5_service.delete_account(mt5_login):
                        logger.info(f"Successfully deleted MT5 account: {mt5_login}")
                    else:
                        logger.error(f"Failed to delete MT5 account: {mt5_login}")
                    logger.info("Rolled back MT5 account creation for " + mt5_login)
                except Exception as delete_error:
                    logger.error(f"Error deleting MT5 account {mt5_login}: {str(delete_error)}")

                return Response({
                    'error': 'Database error',
                    'details': 'Failed to create account record'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.error(f"Error creating trading account: {str(e)}")
            return Response({
                'error': 'Server error',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OpenPositionsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, **kwargs):
        try:
            # Handle both mam_id and account_id for backwards compatibility
            account_id = kwargs.get('account_id') or kwargs.get('mam_id')
            if not account_id:
                return Response(
                    {"error": "Account ID is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
                
            raw_positions = MT5ManagerActions().get_open_positions(int(account_id))
            
            # Map MT5 position fields to frontend expected fields
            formatted_positions = []
            for pos in raw_positions:
                formatted_positions.append({
                    "ticket": pos.get("id", ""),
                    "symbol": pos.get("symbol", ""),
                    "type": pos.get("type", ""),
                    "volume": pos.get("volume", 0),
                    "openPrice": pos.get("price", 0),
                    "currentPrice": pos.get("price", 0),  # MT5 doesn't provide current price in position data
                    "sl": 0,  # Stop Loss - not provided by current MT5 implementation
                    "tp": 0,  # Take Profit - not provided by current MT5 implementation
                    "profit": pos.get("profit", 0),
                    "swap": 0,  # Swap - not provided by current MT5 implementation
                    "openTime": pos.get("date", ""),
                    "comment": ""  # Comment - not provided by current MT5 implementation
                })
            
            return Response({"positions": formatted_positions}, status=200)
        except Exception as e:
            return Response({"error": f"Failed to fetch open positions: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TransactionHistoryView(APIView):
    """
    API to fetch transaction history for a trading account.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests to retrieve transaction history.
        """
        account_id = request.query_params.get('account_id')

        if not account_id:
            return Response(
                {"error": "Account ID is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Verify account ownership - never trust client-provided IDs
            account = get_object_or_404(TradingAccount, account_id=account_id, user=request.user)
            
            transactions = Transaction.objects.filter(
                trading_account=account,
            ).exclude(status='pending')

            if not transactions.exists():
                return Response(
                    {"transactions": []},  
                    status=status.HTTP_200_OK
                )

            serializer = TransactionSerializer(transactions, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except TradingAccount.DoesNotExist:
            return Response(
                {"error": "Account not found or you do not have permission to access it."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
       
@method_decorator(csrf_exempt, name="dispatch")
class ForgotPasswordView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        email = data.get("email")
        if not email:
            return JsonResponse({"success": False, "error": "Email is required"}, status=400)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({"success": False, "error": "User not found"}, status=404)

        user.generate_otp()

        
        subject = "Your Password Reset OTP"
        html_message = render_to_string("emails/otp_email.html", {"otp": user.otp})
        email = EmailMessage(
            subject=subject,
            body=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.content_subtype = "html"  
        email.send()
        return JsonResponse({"success": True, "message": "OTP sent to your email"}, status=200)

@method_decorator(csrf_exempt, name="dispatch")
class VerifyOtpView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        email = data.get("email")
        otp = data.get("otp")

        if not email or not otp:
            return JsonResponse({"success": False, "error": "Email and OTP are required"}, status=400)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({"success": False, "error": "User not found"}, status=404)

        if user.is_otp_valid(otp):
            return JsonResponse({"success": True, "message": "OTP verified"}, status=200)
        else:
            return JsonResponse({"success": False, "error": "Invalid or expired OTP"}, status=400)

@method_decorator(csrf_exempt, name="dispatch")
class ResetPasswordView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return JsonResponse({"success": False, "error": "Email and new password are required"}, status=400)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({"success": False, "error": "User not found"}, status=404)

        
        user.set_password(password)
        user.otp = None  
        user.save()

        
        ActivityLog.objects.create(
            user=user,
            activity="Password reset successfully.",
            ip_address=get_client_ip(request),
            endpoint=request.path,
            activity_type="update",
            activity_category="client",
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            timestamp=now()
        )

        return JsonResponse({"success": True, "message": "Password reset successful"}, status=200)

class IBRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve the IB request status for the logged-in user."""
        try:
            ib_request = IBRequest.objects.get(user=request.user)
            # Use user's actual IB_status as the source of truth
            serializer = IBRequestSerializer(ib_request)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except IBRequest.DoesNotExist:
            return Response({"status": "No IB request found."}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        """Create a new IB request if one does not already exist."""
        ibrequest = IBRequest.objects.filter(user=request.user).first()
        if ibrequest:
            ibrequest.status = "pending"
            ibrequest.save()
            serializer = IBRequestSerializer(ibrequest)

            
            ActivityLog.objects.create(
                user=request.user,
                activity="Updated IB request status to 'pending'.",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="update",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=now(),
                related_object_id=ibrequest.id,
                related_object_type="IBRequest"
            )

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        ib_request = IBRequest.objects.create(user=request.user)
        serializer = IBRequestSerializer(ib_request)

        
        ActivityLog.objects.create(
            user=request.user,
            activity="Created a new IB request.",
            ip_address=get_client_ip(request),
            endpoint=request.path,
            activity_type="create",
            activity_category="client",
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            timestamp=now(),
            related_object_id=ib_request.id,
            related_object_type="IBRequest"
        )

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class UpdateDemoAccountView(APIView):
    """Update demo account balance or leverage"""
    
    def post(self, request):
        try:
            account_id = request.data.get('account_id')
            balance = request.data.get('balance')
            leverage = request.data.get('leverage')
            
            if not account_id:
                return Response({'success': False, 'error': 'Account ID is required'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Get the demo account
            try:
                demo_account = DemoAccount.objects.get(account_id=account_id, user=request.user)
            except DemoAccount.DoesNotExist:
                return Response({'success': False, 'error': 'Demo account not found'}, status=status.HTTP_404_NOT_FOUND)
            
            try:
                mt5action = MT5ManagerActions()
                
                if not mt5action.manager:
                    return Response({
                        'success': False,
                        'error': 'MT5 service is currently unavailable. Please try again later.'
                    }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
                
                results = []
                
                # Update balance if provided
                if balance is not None:
                    try:
                        balance = float(balance)
                        if balance < 0:
                            return Response({'success': False, 'error': 'Balance cannot be negative'}, status=status.HTTP_400_BAD_REQUEST)
                        
                        # Get current balance to calculate difference
                        current_user = mt5action.manager.UserGet(int(account_id))
                        if current_user:
                            current_balance = getattr(current_user, 'Balance', 0)
                            balance_diff = balance - current_balance
                            
                            if abs(balance_diff) > 0.01:  # Only update if difference is significant
                                if balance_diff > 0:
                                    # Deposit the difference
                                    if mt5action.deposit_funds(int(account_id), balance_diff, "Balance adjustment"):
                                        demo_account.balance = Decimal(str(balance))
                                        results.append(f"Balance updated to ${balance:,.2f}")
                                    else:
                                        results.append("Failed to update balance in MT5")
                                else:
                                    # Withdraw the difference
                                    if mt5action.withdraw_funds(int(account_id), abs(balance_diff), "Balance adjustment"):
                                        demo_account.balance = Decimal(str(balance))
                                        results.append(f"Balance updated to ${balance:,.2f}")
                                    else:
                                        results.append("Failed to update balance in MT5")
                            else:
                                results.append("Balance is already at the target amount")
                        else:
                            results.append("Failed to get current balance from MT5")
                            
                    except (ValueError, TypeError):
                        return Response({'success': False, 'error': 'Invalid balance value'}, status=status.HTTP_400_BAD_REQUEST)
                    except Exception as e:
                        results.append(f"Balance update failed: {str(e)}")
                
                # Update leverage if provided
                if leverage is not None:
                    try:
                        leverage = int(leverage)
                        if leverage <= 0:
                            return Response({'success': False, 'error': 'Leverage must be positive'}, status=status.HTTP_400_BAD_REQUEST)
                        
                        if mt5action.change_leverage(int(account_id), leverage):
                            demo_account.leverage = str(leverage)
                            results.append(f"Leverage updated to 1:{leverage}")
                        else:
                            results.append("Failed to update leverage in MT5")
                            
                    except (ValueError, TypeError):
                        return Response({'success': False, 'error': 'Invalid leverage value'}, status=status.HTTP_400_BAD_REQUEST)
                    except Exception as e:
                        results.append(f"Leverage update failed: {str(e)}")
                
                # Save changes to database
                if any("updated" in result for result in results):
                    demo_account.save()
                    
                    # Create activity log
                    ActivityLog.objects.create(
                        user=request.user,
                        activity=f"Updated demo account {account_id}: {'; '.join(results)}",
                        ip_address=get_client_ip(request),
                        endpoint=request.path,
                        activity_type="update",
                        activity_category="client",
                        user_agent=request.META.get("HTTP_USER_AGENT", ""),
                        timestamp=now(),
                        related_object_id=demo_account.id,
                        related_object_type="DemoAccount"
                    )
                
                if results:
                    return Response({
                        'success': True,
                        'message': '; '.join(results),
                        'account_id': account_id,
                        'new_balance': str(demo_account.balance),
                        'new_leverage': demo_account.leverage
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({'success': False, 'error': 'No updates provided'}, status=status.HTTP_400_BAD_REQUEST)
                    
            except Exception as e:
                logger.error(f"Error updating demo account {account_id}: {str(e)}")
                return Response({
                    'success': False,
                    'error': f'Failed to update demo account: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"Error in UpdateDemoAccountView: {str(e)}")
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

