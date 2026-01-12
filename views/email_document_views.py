"""
Email-based document lookup views for optimized verification system
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Q
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
import logging

from adminPanel.models import CustomUser
from clientPanel.models import UserDocument
from adminPanel.permissions import IsAdmin, IsManager, IsAuthenticatedUser

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name='dispatch')
class EmailBasedDocumentLookupView(APIView):
    """
    API View for retrieving user documents by email address.
    Optimized for faster lookup without using database index numbers.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, email=None, document_type=None):
        """
        Get documents by email address
        
        URL patterns:
        - /documents/by-email/{email}/ - All documents for user
        - /documents/by-email/{email}/{document_type}/ - Specific document type
        """
        try:
            # Validate email parameter
            if not email:
                return Response(
                    {'error': 'Email parameter is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                validate_email(email)
            except ValidationError:
                return Response(
                    {'error': 'Invalid email format'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if current user has permission to view these documents
            # Users can only view their own documents, admins/managers can view any
            if (request.user.email != email and 
                not (hasattr(request.user, 'role') and 
                     request.user.role in ['admin', 'manager'])):
                return Response(
                    {'error': 'Permission denied'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Build query filter
            query_filter = {'user_email': email}
            if document_type:
                if document_type not in ['identity', 'residence']:
                    return Response(
                        {'error': 'Invalid document type. Must be "identity" or "residence"'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                query_filter['document_type'] = document_type

            # Optimized query using email index
            documents = UserDocument.objects.filter(
                **query_filter
            ).select_related('user').order_by('-uploaded_at')

            if document_type:
                # Return single document
                document = documents.first()
                if not document:
                    return Response({
                        'status': 'not_uploaded',
                        'document_type': document_type,
                        'user_email': email,
                        'message': f'No {document_type} document found for {email}'
                    })
                
                return Response({
                    'id': document.id,
                    'status': document.status,
                    'document_type': document.document_type,
                    'document_url': document.document.url if document.document else None,
                    'user_email': document.user_email,
                    'uploaded_at': document.uploaded_at.isoformat() if document.uploaded_at else None,
                    'verified_at': document.verified_at.isoformat() if document.verified_at else None,
                    'mime_type': document.mime_type,
                    'user_id': document.user.user_id if document.user else None
                })
            else:
                # Return all documents
                doc_list = []
                for doc in documents:
                    doc_list.append({
                        'id': doc.id,
                        'status': doc.status,
                        'document_type': doc.document_type,
                        'document_url': doc.document.url if doc.document else None,
                        'user_email': doc.user_email,
                        'uploaded_at': doc.uploaded_at.isoformat() if doc.uploaded_at else None,
                        'verified_at': doc.verified_at.isoformat() if doc.verified_at else None,
                        'mime_type': doc.mime_type,
                        'user_id': doc.user.user_id if doc.user else None
                    })
                
                return Response({
                    'user_email': email,
                    'total_documents': len(doc_list),
                    'documents': doc_list
                })

        except Exception as e:
            logger.error(f"Error in email-based document lookup: {e}", exc_info=True)
            return Response(
                {'error': 'Internal server error', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_documents_by_status(request, email, doc_status):
    """
    Get documents by email and status for admin filtering
    
    URL: /documents/by-email/{email}/status/{status}/
    """
    try:
        # Validate email
        try:
            validate_email(email)
        except ValidationError:
            return Response(
                {'error': 'Invalid email format'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate status
        valid_statuses = ['pending', 'approved', 'rejected']
        if doc_status not in valid_statuses:
            return Response(
                {'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check permissions
        if (request.user.email != email and 
            not (hasattr(request.user, 'role') and 
                 request.user.role in ['admin', 'manager'])):
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Optimized query using composite index
        documents = UserDocument.objects.filter(
            user_email=email,
            status=doc_status
        ).select_related('user').order_by('-uploaded_at')

        doc_list = []
        for doc in documents:
            doc_list.append({
                'id': doc.id,
                'status': doc.status,
                'document_type': doc.document_type,
                'document_url': doc.document.url if doc.document else None,
                'user_email': doc.user_email,
                'uploaded_at': doc.uploaded_at.isoformat() if doc.uploaded_at else None,
                'verified_at': doc.verified_at.isoformat() if doc.verified_at else None,
                'mime_type': doc.mime_type,
                'user_id': doc.user.user_id if doc.user else None
            })

        return Response({
            'user_email': email,
            'status_filter': doc_status,
            'total_documents': len(doc_list),
            'documents': doc_list
        })

    except Exception as e:
        logger.error(f"Error getting documents by status: {e}", exc_info=True)
        return Response(
            {'error': 'Internal server error', 'details': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def bulk_document_status(request):
    """
    Get document status for multiple emails at once
    
    URL: /documents/bulk-status/?emails=email1,email2,email3
    """
    try:
        # Check admin permissions
        if not (hasattr(request.user, 'role') and 
                request.user.role in ['admin', 'manager']):
            return Response(
                {'error': 'Admin or Manager access required'},
                status=status.HTTP_403_FORBIDDEN
            )

        emails_param = request.GET.get('emails', '')
        if not emails_param:
            return Response(
                {'error': 'emails parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        emails = [email.strip() for email in emails_param.split(',') if email.strip()]
        if not emails:
            return Response(
                {'error': 'At least one valid email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate all emails
        for email in emails:
            try:
                validate_email(email)
            except ValidationError:
                return Response(
                    {'error': f'Invalid email format: {email}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Optimized bulk query
        documents = UserDocument.objects.filter(
            user_email__in=emails
        ).select_related('user').order_by('user_email', 'document_type')

        # Group by email
        result = {}
        for email in emails:
            result[email] = {
                'identity': {'status': 'not_uploaded', 'document': None},
                'residence': {'status': 'not_uploaded', 'document': None}
            }

        for doc in documents:
            result[doc.user_email][doc.document_type] = {
                'id': doc.id,
                'status': doc.status,
                'document_url': doc.document.url if doc.document else None,
                'uploaded_at': doc.uploaded_at.isoformat() if doc.uploaded_at else None,
                'verified_at': doc.verified_at.isoformat() if doc.verified_at else None,
                'mime_type': doc.mime_type
            }

        return Response({
            'total_emails': len(emails),
            'results': result
        })

    except Exception as e:
        logger.error(f"Error in bulk document status: {e}", exc_info=True)
        return Response(
            {'error': 'Internal server error', 'details': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )