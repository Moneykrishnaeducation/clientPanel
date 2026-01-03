from django.http import HttpResponse, JsonResponse
from django.views.static import serve
import os
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from ..models import AccountDetails, BankDetails
from adminPanel.models import CryptoDetails
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.shortcuts import render

def serve_client_app(request):
    """Serve the client application's index.html for all non-API routes."""
    # Check if this is an API request
    if request.path.startswith('/api/'):
        return HttpResponse("API endpoint not found", status=404)

    # Check if this is a static file request
    if request.path.startswith('/static/'):
        return serve(request, request.path[8:], document_root=settings.STATIC_ROOT)
        
    # Serve ib-request.html for /ib-request/ path
    if request.path == '/ib-request/':
        file_path = os.path.join(settings.BASE_DIR, 'static', 'client', 'pages', 'ib-request.html')
    else:
        file_path = os.path.join(settings.BASE_DIR, 'static', 'clientPanel', 'index.html')
    try:
        with open(file_path, 'rb') as file:
            content_type = 'text/html'
            response = HttpResponse(file.read(), content_type=content_type)
            response['X-Frame-Options'] = 'DENY'
            response['X-Content-Type-Options'] = 'nosniff'
            response['Cache-Control'] = 'no-cache'
            return response
    except FileNotFoundError:
        return HttpResponse("Client app not found. Please ensure the client application is built and copied to the static directory.", status=404)

@login_required
@require_http_methods(["GET"])
def get_account_details(request):
    try:
        details = AccountDetails.objects.filter(user=request.user).first()
        if not details:
            return JsonResponse({
                'success': False,
                'message': 'Account details not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'data': {
                'balance': details.balance,
                'account_type': details.account_type,
                'status': details.status
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        }, status=500)

@login_required
@require_http_methods(["GET"])
def get_bank_details(request):
    try:
        details = BankDetails.objects.filter(user=request.user).first()
        if not details:
            return JsonResponse({
                'success': False,
                'message': 'Bank details not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'data': {
                'bank_name': details.bank_name,
                'account_number': details.account_number,
                'swift_code': details.swift_code
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        }, status=500)

@login_required
@require_http_methods(["GET"])
def get_crypto_details(request):
    try:
        details = CryptoDetails.objects.filter(user=request.user).first()
        if not details:
            return JsonResponse({
                'success': False,
                'message': 'Crypto details not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'data': {
                'wallet_address': details.wallet_address,
                'currency': details.currency
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        }, status=500)



def pamm_client_view(request):
    """Serve the PAMM client application with proper CSRF token."""

    
    # Try JWT authentication first (for iframe context)
    user = None
    
    # Check for JWT token in URL parameter (for iframe)
    jwt_token = request.GET.get('token')
    if jwt_token:
        try:
            jwt_auth = JWTAuthentication()
            validated_token = jwt_auth.get_validated_token(jwt_token)
            user = jwt_auth.get_user(validated_token)
        except (InvalidToken, TokenError) as e:
            print(f"JWT URL parameter authentication failed: {e}")
    
    # Check for JWT token in Authorization header
    if not user:
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                jwt_auth = JWTAuthentication()
                validated_token = jwt_auth.get_validated_token(auth_header.split(' ')[1])
                user = jwt_auth.get_user(validated_token)
            except (InvalidToken, TokenError) as e:
                print(f"JWT authorization header authentication failed: {e}")
    
    # Check for JWT token in cookies (fallback)
    if not user:
        jwt_token = request.COOKIES.get('jwt_token')
        if jwt_token:
            try:
                jwt_auth = JWTAuthentication()
                validated_token = jwt_auth.get_validated_token(jwt_token)
                user = jwt_auth.get_user(validated_token)
            except (InvalidToken, TokenError) as e:
                print(f"JWT cookie authentication failed: {e}")
    
    # Use session authentication as fallback
    if not user and request.user.is_authenticated:
            user = request.user
        # print(f"Session authentication successful for user: {user}")
    
    # Check if user is authenticated
    if not user or not user.is_authenticated:
        # Return a simple message for iframe context
        return HttpResponse('<html><body><p>Please login to access PAMM accounts.</p></body></html>', 
                          content_type='text/html', status=401)
    
    # Set the authenticated user for the template context
    request.user = user
    response = render(request, 'clientPanel/pamm.html')
    
    # Allow iframe loading from same origin for compatibility with main client app
    response['X-Frame-Options'] = 'SAMEORIGIN'
    response['X-Content-Type-Options'] = 'nosniff'
    response['Cache-Control'] = 'no-cache'
    
    return response
