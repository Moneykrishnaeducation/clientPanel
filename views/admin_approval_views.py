from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from clientPanel.models import BankDetails, UserDocument
from adminPanel.models import CryptoDetails, ActivityLog
from clientPanel.serializers import BankDetailsSerializer, CryptoDetailsSerializer
from adminPanel.permissions import IsAdminOrManager
import logging

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class PendingRequestsView(APIView):
    """Get all pending profile requests for admin approval"""
    permission_classes = [IsAuthenticated, IsAdminOrManager]
    
    def get(self, request):
        try:
            # Get all pending requests
            pending_bank_details = BankDetails.objects.filter(status='pending').select_related('user')
            pending_crypto_details = CryptoDetails.objects.filter(status='pending').select_related('user')
            pending_documents = UserDocument.objects.filter(status='pending').select_related('user')
            
            # Format response
            response_data = {
                'bank_details': [
                    {
                        'id': bd.id,
                        'user': {
                            'id': bd.user.id,
                            'email': bd.user.email,
                            'name': f"{bd.user.first_name} {bd.user.last_name}"
                        },
                        'bank_name': bd.bank_name,
                        'account_number': bd.account_number,
                        'ifsc_code': bd.ifsc_code,
                        'branch_name': bd.branch_name,
                        'created_at': bd.created_at,
                        'type': 'bank_details'
                    } for bd in pending_bank_details
                ],
                'crypto_details': [
                    {
                        'id': cd.id,
                        'user': {
                            'id': cd.user.id,
                            'email': cd.user.email,
                            'name': f"{cd.user.first_name} {cd.user.last_name}"
                        },
                        'wallet_address': cd.wallet_address,
                        'currency': cd.currency,
                        'created_at': cd.created_at,
                        'type': 'crypto_details'
                    } for cd in pending_crypto_details
                ],
                'documents': [
                    {
                        'id': doc.id,
                        'user': {
                            'id': doc.user.id,
                            'email': doc.user.email,
                            'name': f"{doc.user.first_name} {doc.user.last_name}"
                        },
                        'document_type': doc.document_type,
                        'document_url': doc.document.url if doc.document else None,
                        'uploaded_at': doc.uploaded_at,
                        'type': 'document'
                    } for doc in pending_documents
                ]
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching pending requests: {str(e)}")
            return Response(
                {'error': 'Failed to fetch pending requests'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(csrf_exempt, name='dispatch')
class ApprovalActionView(APIView):
    """Handle approval/rejection of profile requests"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # Check if user is admin
            if not request.user.is_staff and request.user.role != 'admin':
                return Response(
                    {'error': 'Admin access required'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            item_type = request.data.get('type')
            item_id = request.data.get('id')
            action = request.data.get('action')  # 'approve' or 'reject'
            reason = request.data.get('reason', '')
            
            if not all([item_type, item_id, action]):
                return Response(
                    {'error': 'Missing required fields: type, id, action'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if action not in ['approve', 'reject']:
                return Response(
                    {'error': 'Action must be "approve" or "reject"'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get the appropriate model and item
            if item_type == 'bank_details':
                item = get_object_or_404(BankDetails, id=item_id)
                item_description = f"Bank details for {item.user.email}"
            elif item_type == 'crypto_details':
                item = get_object_or_404(CryptoDetails, id=item_id)
                item_description = f"Crypto details for {item.user.email}"
            elif item_type == 'document':
                item = get_object_or_404(UserDocument, id=item_id)
                item_description = f"{item.get_document_type_display()} for {item.user.email}"
            else:
                return Response(
                    {'error': 'Invalid type. Must be: bank_details, crypto_details, or document'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            

            # Update status
            new_status = 'approved' if action == 'approve' else 'rejected'
            item.status = new_status
            item.save()

            # Send KYC verified email if UserDocument is approved
            if item_type == 'document' and new_status == 'approved':
                from adminPanel.EmailSender import EmailSender
                from django.utils import timezone
                user = item.user
                user_name = user.get_full_name() if hasattr(user, 'get_full_name') else user.username
                login_url = 'https://client.vtindex.com'
                support_url = 'support@vtindex.com'  # Change if needed
                current_year = timezone.now().year
                logger.info(f"Triggering KYC verified email for user {user.email} (document id: {item.id})")
                result = EmailSender.send_kyc_verified_email(
                    user.email,
                    user_name,
                    login_url,
                    support_url,
                    current_year
                )
                logger.info(f"KYC verified email send result: {result}")
            
            # Log the action
            try:
                ActivityLog.objects.create(
                    user=request.user,
                    activity=f"Admin {action}d {item_description}",
                    activity_type="update",
                    details=f"Status changed to {new_status}. Reason: {reason}" if reason else f"Status changed to {new_status}"
                )
            except Exception as log_error:
                logger.warning(f"Failed to create activity log: {log_error}")
            
            return Response({
                'message': f'Successfully {action}d {item_description}',
                'type': item_type,
                'id': item_id,
                'new_status': new_status
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error processing approval action: {str(e)}")
            return Response(
                {'error': 'Failed to process approval action'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(csrf_exempt, name='dispatch')  
class UserVerificationStatusView(APIView):
    """Get verification status for a specific user"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id):
        try:
            # Check if user is admin/manager or viewing own profile
            is_admin_or_manager = IsAdminOrManager().has_permission(request, self)
            is_own_profile = request.user.id == user_id
            
            if not (is_admin_or_manager or is_own_profile):
                return Response(
                    {'error': 'Access denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            from adminPanel.models import CustomUser
            user = get_object_or_404(CustomUser, id=user_id)
            
            # Get verification statuses
            bank_details = BankDetails.objects.filter(user=user).first()
            crypto_details = CryptoDetails.objects.filter(user=user).first()
            identity_doc = UserDocument.objects.filter(user=user, document_type='identity').first()
            residence_doc = UserDocument.objects.filter(user=user, document_type='residence').first()
            
            verification_status = {
                'user_id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}",
                'bank_details_status': bank_details.status if bank_details else 'not_submitted',
                'crypto_details_status': crypto_details.status if crypto_details else 'not_submitted',
                'identity_document_status': identity_doc.status if identity_doc else 'not_submitted',
                'residence_document_status': residence_doc.status if residence_doc else 'not_submitted',
                'overall_verified': all([
                    bank_details and bank_details.status == 'approved',
                    crypto_details and crypto_details.status == 'approved',
                    identity_doc and identity_doc.status == 'approved',
                    residence_doc and residence_doc.status == 'approved'
                ])
            }
            
            return Response(verification_status, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching user verification status: {str(e)}")
            return Response(
                {'error': 'Failed to fetch verification status'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
