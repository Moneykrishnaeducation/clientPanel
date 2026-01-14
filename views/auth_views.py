from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.middleware.csrf import get_token
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from adminPanel.models import CustomUser
from adminPanel.EmailSender import EmailSender
from django.utils import timezone
import random
import secrets
import jwt
from jwt import PyJWKClient
from adminPanel.models import ActivityLog
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.urls import reverse
from django.conf import settings
import logging
from datetime import timedelta
import time
from django.db.models import Q
from clientPanel import tasks as client_tasks
from django.core.cache import cache
import threading
import requests
from django.core.files.base import ContentFile
from urllib.parse import urlparse, urlencode
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
import os
from datetime import datetime
from brokerBackend.cookie_manager import CookieManager
import hashlib

logger = logging.getLogger(__name__)

def hash_otp(otp):
    """Hash OTP with salt for secure storage"""
    salt = secrets.token_hex(16)  # Random 16-byte salt
    otp_hash = hashlib.pbkdf2_hmac(
        'sha256',
        otp.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Iterations
    )
    return f"{salt}${otp_hash.hex()}"

def verify_otp(stored_hash, provided_otp):
    """Verify provided OTP against stored hash"""
    try:
        salt, otp_hash = stored_hash.split('$')
        provided_hash = hashlib.pbkdf2_hmac(
            'sha256',
            provided_otp.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return provided_hash == otp_hash
    except Exception:
        return False

def hash_password(password):
    """Hash password with salt for secure storage (hash+salt format)"""
    salt = secrets.token_hex(16)  # Random 16-byte salt
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Iterations
    )
    return f"{salt}${password_hash.hex()}"

def verify_password(stored_hash, provided_password):
    """Verify provided password against stored hash+salt"""
    try:
        salt, password_hash = stored_hash.split('$')
        provided_hash = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return provided_hash == password_hash
    except Exception:
        return False

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def _check_rate_limit(key, limit, period_seconds):
    """Return True if the key is currently rate-limited.

    Uses Django cache to store a counter with TTL `period_seconds`.
    """
    try:
        val = cache.get(key)
        if val is None:
            # initialize counter
            cache.set(key, 1, timeout=period_seconds)
            return False
        if val >= limit:
            return True
        # try to increment atomically where supported
        try:
            cache.incr(key)
        except Exception:
            # fall back to set
            cache.set(key, val + 1, timeout=period_seconds)
        return False
    except Exception:
        # If cache backend fails, avoid blocking requests (fail-open)
        return False


def compute_redirect_url(request, frontend_role):
    """Compute redirect URL based on request host and user role.

    Preference order:
    - If a `role` or `UserRole` cookie is present, use that as the role.
    - Otherwise use the provided `frontend_role`.

    Mapping rules:
    - Manager on admin host -> `/manager/dashboard`
    - Manager otherwise -> `/dashboard`
    - Admin -> `/dashboard` (admin dashboard path on admin host)
    - All others -> `/dashboard`
    """
    try:
        host = (request.get_host() or '').lower()
    except Exception:
        host = ''

    cookie_role = (request.COOKIES.get('role') or request.COOKIES.get('UserRole') or '').strip().lower()
    if cookie_role:
        role = cookie_role
    else:
        try:
            role = str(frontend_role).lower()
        except Exception:
            role = 'client'

    is_admin_host = 'admin.' in host or host.startswith('admin') or host.endswith('admin')

    if role == 'manager':
        return '/manager/dashboard/' if is_admin_host else '/dashboard/'
    if role == 'admin':
        return '/dashboard/'
    return '/dashboard/'

@csrf_exempt
@api_view(['POST', 'OPTIONS'])
@permission_classes([AllowAny])
def signup_view(request):
    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['X-CSRFToken'] = get_token(request)
        return response
        
    data = request.data
    email = data.get('email')
    password = data.get('password')
    name = data.get('name', '').split(maxsplit=1)
    referral_code = data.get('referral_code')  # <-- Get referral code from request

    # Basic validation
    if not all([email, password, name]):
        return Response({
            'error': 'Email, password, and name are required'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Check if user already exists
    if CustomUser.objects.filter(email=email).exists():
        return Response({
            'error': 'A user with this email already exists'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Create user
        first_name = name[0]
        last_name = name[1] if len(name) > 1 else ''

        # If referral_code is present, try to find the parent IB
        parent_ib = None
        if referral_code:
            parent_ib = CustomUser.objects.filter(referral_code=referral_code, IB_status=True).first()

        # Hash password with salt+hash format
        hashed_password = hash_password(password)
        
        user = CustomUser.objects.create(
            username=email,
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            manager_admin_status='Client',  # Set as client
            parent_ib=parent_ib if parent_ib else None,
            referral_code_used=referral_code if referral_code else None
        )
        user.set_password(hashed_password)  # Use the hashed password
        user.save()
        
        # Send welcome email
        try:
            # logger.info(f"Attempting to send welcome email to new user {email}")
            welcome_email_sent = EmailSender.send_welcome_email(email, first_name)
            if not welcome_email_sent:
                logger.warning(f"Failed to send welcome email to {email}")
        except Exception as e:
            logger.error(f"Error sending welcome email to {email}: {str(e)}")
            # We don't want to rollback registration if email fails
            pass
        # Also send the 'new user from admin' styled email (best-effort).
        # Some flows (internal or marketing) use this template which includes
        # credentials and next steps. Send it for client signups as well.
        try:
            new_user_email_sent = EmailSender.send_new_user_from_admin(email, first_name, password)
            if not new_user_email_sent:
                logger.warning(f"Failed to send new_user_from_admin email to {email}")
        except Exception as e:
            logger.error(f"Error sending new_user_from_admin email to {email}: {str(e)}")
            # Do not fail registration if this email fails
            pass
        
        # Log activity
        ActivityLog.objects.create(
            user=user,
            activity="New user signup via client portal",
            ip_address=get_client_ip(request),
            endpoint=request.path,
            activity_type="create",
            activity_category="client",
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            timestamp=timezone.now(),
            related_object_id=user.id,
            related_object_type="Client Registration"
        )
        
        # Auto-login the user after successful registration
        refresh = RefreshToken.for_user(user)
        # Ensure client tokens are marked correctly
        try:
            refresh['aud'] = 'client.vtindex'
            refresh['scope'] = 'client:*'
            access = refresh.access_token
            access['aud'] = 'client.vtindex'
            access['scope'] = 'client:*'
        except Exception:
            pass

        # Parse remember flag from request (accept booleans or strings)
        remember_val = data.get('remember', False)
        try:
            remember = str(remember_val).lower() in ('1', 'true', 'yes', 'on')
        except Exception:
            remember = False

        # Determine lifetimes: when remember is true, extend to 7 days; otherwise use defaults
        from datetime import timedelta
        remember_refresh_lifetime = timedelta(days=7)
        remember_access_lifetime = timedelta(days=7)

        default_refresh_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('REFRESH_TOKEN_LIFETIME', timedelta(days=1))
        default_access_lifetime = timedelta(hours=1)

        if remember:
            refresh_lifetime = remember_refresh_lifetime
            access_lifetime = remember_access_lifetime
        else:
            refresh_lifetime = default_refresh_lifetime
            access_lifetime = default_access_lifetime

        # Apply custom expirations to refresh and derived access token
        try:
            refresh.set_exp(from_time=refresh.current_time, lifetime=refresh_lifetime)
            access = refresh.access_token
            access.set_exp(from_time=access.current_time, lifetime=access_lifetime)
            try:
                access.outstand()
            except Exception:
                logger.exception('Failed to create OutstandingToken for newly issued access (signup_view)')
            access_token = str(access)
        except Exception:
            # Fallback to default issued tokens
            try:
                # Attempt to record outstanding on fallback access token as best-effort
                fallback_access = refresh.access_token
                try:
                    fallback_access.outstand()
                except Exception:
                    logger.exception('Failed to create OutstandingToken for newly issued access (signup_view - fallback)')
                access_token = str(fallback_access)
            except Exception:
                access_token = str(refresh)
        
        # Determine user role for frontend
        role_mapping = {
            'Admin': 'admin',
            'Manager': 'manager', 
            'Client': 'client'
        }
        frontend_role = role_mapping.get(user.manager_admin_status, 'client')
        
        resp_body = {
            'success': True,
            'message': 'Registration successful! Welcome to VT-Index!',
            'access': access_token,
            'refresh': str(refresh),
            'role': frontend_role,
            'auto_login': True,
            'remember': remember,
            'user': {
                'email': user.email,
                'name': f'{user.first_name} {user.last_name}'.strip()
            }
        }

        response = Response(resp_body)
        # Also set HttpOnly cookies for API and client usage using CookieManager
        try:
            access = resp_body.get('access')
            refresh_val = resp_body.get('refresh')
            secure_flag = not settings.DEBUG
            
            # Use CookieManager to set cookies with auto-clear support
            try:
                tokens_dict = {
                    'access': access,
                    'refresh': refresh_val
                }
                user_data = {
                    'username': user.email,
                    'email': user.email,
                    'role': frontend_role
                }
                
                client_ip = get_client_ip(request)
                
                response = CookieManager.set_auth_cookies(
                    response=response,
                    tokens_dict=tokens_dict,
                    user_data=user_data,
                    remember_me=remember,
                    secure_flag=secure_flag,
                    cookie_domain=None,
                    user_id=user.id,
                    ip_address=client_ip
                )
                
                # Expose role to frontend via non-HttpOnly cookie
                response.set_cookie('role', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/')
                response.set_cookie('UserRole', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/')
                
            except Exception:
                logger.exception("Failed to set cookies using CookieManager; using fallback method")
                
                # Fallback: set cookies manually
                try:
                    refresh_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('REFRESH_TOKEN_LIFETIME', None)
                    access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
                    refresh_max_age = int(refresh_lifetime.total_seconds()) if refresh_lifetime else None
                    access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
                except Exception:
                    refresh_max_age = None
                    access_max_age = None

                if access:
                    response.set_cookie('jwt_token', access, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
                    response.set_cookie('access_token', access, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
                if refresh_val:
                    response.set_cookie('refresh_token', refresh_val, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=refresh_max_age)
                # Expose role to frontend via non-HttpOnly cookie and legacy name `UserRole`
                try:
                    response.set_cookie('role', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/', max_age=access_max_age)
                    response.set_cookie('UserRole', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/', max_age=access_max_age)
                except Exception:
                    logger.exception('Failed to set role cookies on signup response')
        except Exception:
            logger.exception('Failed to set auth cookies on signup response')

        return response
        
    except Exception as e:
        logger.error(f"Failed to create account for {email}: {str(e)}")
        return Response({
            'error': 'Failed to create account. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(['POST', 'OPTIONS'])
@permission_classes([AllowAny])
def client_login_view(request):
    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['X-CSRFToken'] = get_token(request)
        return response
        
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        # Log failed login attempt
        try:
            ActivityLog.objects.create(
                user=None,
                activity="Login attempt - missing email or password",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=400,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to create failed login ActivityLog")
        return Response({
            'error': 'Both email and password are required',
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Parse remember flag from request (accept booleans or strings)
    remember_val = request.data.get('remember', False)
    try:
        remember = str(remember_val).lower() in ('1', 'true', 'yes', 'on')
    except Exception:
        remember = False
    
    # Start timing for diagnostics
    start_t = time.perf_counter()
    # Determine client IP early for rate-limiting and logging
    try:
        current_ip = get_client_ip(request)
    except Exception:
        current_ip = None

    # Enforce IP-based login rate limit (default 5/minute)
    login_limit = getattr(settings, 'LOGIN_RATE_LIMIT_PER_MINUTE', 5)
    if current_ip:
        rl_key = f"rl:login:ip:{current_ip}"
        if _check_rate_limit(rl_key, login_limit, 60):
            return Response({'error': 'Too many login attempts from your IP. Try again later.'}, status=429)

    # Single optimized DB query for user by email OR username. Limit selected fields
    user = CustomUser.objects.only('id', 'email', 'username', 'password', 'manager_admin_status', 'first_name', 'last_name')\
        .filter(Q(email__iexact=email) | Q(username__iexact=email)).first()

    if not user:
        # Log failed login attempt
        try:
            ActivityLog.objects.create(
                user=None,
                activity=f"Login attempt - user not found: {email}",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=401,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to create user-not-found ActivityLog")
        return Response({'error': 'Invalid credentials', 'message': 'Please check your email and password'}, status=status.HTTP_401_UNAUTHORIZED)

    # Verify password using hash+salt verification
    if not verify_password(user.password, password):
        # Log failed login attempt
        try:
            ActivityLog.objects.create(
                user=user,
                activity="Login attempt - invalid password",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=401,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to create invalid-password ActivityLog")
        return Response({'error': 'Invalid credentials', 'message': 'Please check your email and password'}, status=status.HTTP_401_UNAUTHORIZED)

    # Check if user has access to client panel (allow Client, Admin, and Manager roles)
    allowed_roles = ['admin', 'manager', 'client', 'Admin', 'Manager', 'Client', 'None']
    if user.manager_admin_status not in allowed_roles:
        # Log access denied
        try:
            ActivityLog.objects.create(
                user=user,
                activity="Login attempt - insufficient permissions",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=401,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to create access-denied ActivityLog")
        return Response({'error': 'Access denied: insufficient permissions for client portal'}, status=status.HTTP_401_UNAUTHORIZED)

    # `current_ip` was determined earlier for rate-limiting and is reused here

    # Check previous login IP (best-effort). If previous IP exists and differs, require verification
    try:
        last_log = ActivityLog.objects.filter(user=user).order_by('-timestamp').first()
        last_ip = last_log.ip_address if last_log else None
    except Exception:
        last_ip = None

    # If we have a last IP and it differs from the current one, require OTP verification before issuing tokens
    if last_ip and current_ip and last_ip != current_ip:
        try:
            # Generate login-specific OTP and attach to user (separate from password-reset OTP)
            otp = f"{random.randint(100000, 999999)}"
            # Hash OTP before storing
            hashed_otp = hash_otp(otp)
            user.login_otp = hashed_otp
            user.login_otp_created_at = timezone.now()
            user.save(update_fields=["login_otp", "login_otp_created_at"])

            # Send OTP via email (best-effort)
            email_sent = False
            try:
                # Use the dedicated login OTP email template for clarity
                email_sent = EmailSender.send_login_otp_email(
                    user.email,
                    otp,
                    ip_address=current_ip,
                    login_time=timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                    first_name=user.first_name
                )
            except Exception:
                logger.exception("Failed to send login OTP email to user")

            if not email_sent:
                # If email failed to send, fall back to normal login to avoid lockout
                logger.warning("Login OTP email failed to send; falling back to normal login")
            else:
                # Record that a verification was required (non-blocking)
                try:
                    ActivityLog.objects.create(
                        user=user,
                        activity="Login attempt - verification required (new IP)",
                        ip_address=current_ip,
                        endpoint=request.path,
                        activity_type="update",
                        activity_category="client",
                        status_code=202,
                        user_agent=request.META.get("HTTP_USER_AGENT", ""),
                        timestamp=timezone.now(),
                        related_object_id=user.id,
                        related_object_type="LoginVerification"
                    )
                except Exception:
                    logger.exception("Failed to create ActivityLog for login verification requirement")

                # Tell frontend verification is required. Do not issue tokens yet.
                return Response({
                    'verification_required': True,
                    'message': 'A verification code was sent to your email because this login originates from a new IP address.'
                }, status=status.HTTP_202_ACCEPTED)
        except Exception:
            # If anything in the verification-path fails, log and continue to allow login to avoid lockout
            logger.exception("Error while requiring login verification; falling back to normal login")

    # --- Issue tokens and record login in background for non-new-IP logins ---
    refresh = RefreshToken.for_user(user)

    # Create background task to record login and (if applicable) notify about IP changes
    try:
        def _background_login_tasks():
            try:
                # Best-effort: find last IP (may be None)
                last_log_local = ActivityLog.objects.filter(user=user).order_by('-timestamp').first()
                last_ip_local = last_log_local.ip_address if last_log_local else None

                # Create activity log for this login (non-blocking for caller)
                try:
                    ActivityLog.objects.create(
                        user=user,
                        activity="User login via client portal",
                        ip_address=current_ip,
                        endpoint=request.path,
                        activity_type="update",
                        activity_category="client",
                        status_code=200,
                        user_agent=request.META.get("HTTP_USER_AGENT", ""),
                        timestamp=timezone.now(),
                        related_object_id=user.id,
                        related_object_type="Login"
                    )
                except Exception:
                    logger.exception("Failed to create ActivityLog for login (background)")

                # If IP changed and was not empty, send notification email (best-effort)
                if last_ip_local and current_ip and last_ip_local != current_ip:
                    try:
                        EmailSender.send_new_ip_login_email(
                            user.email,
                            f"{user.first_name} {user.last_name}".strip() or user.email,
                            current_ip,
                            timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                            request.META.get('HTTP_USER_AGENT', '')
                        )
                    except Exception:
                        logger.exception("Failed to send new-IP login email notification (background)")
            except Exception:
                # Fail silently in background to avoid impacting main response
                logger.exception("Unexpected error in background login tasks")

        # Dispatch background tasks to avoid blocking the login response
        try:
            bg_thread = threading.Thread(target=_background_login_tasks, daemon=True)
            bg_thread.start()
        except Exception:
            logger.exception("Failed to start background thread for login tasks")
    except Exception:
        # Surround the whole best-effort block so login always succeeds even if logging/notify fails
        logger.exception("Error while scheduling background login tasks")

    # Determine user role for frontend
    role_mapping = {
        'Admin': 'admin',
        'Manager': 'manager', 
        'Client': 'client',
        'None': 'client'
    }
    frontend_role = role_mapping.get(user.manager_admin_status, 'client')

    # Compute duration and prepare response
    duration_ms = int((time.perf_counter() - start_t) * 1000)

    # Record the issued access token as outstanding so it can be revoked later
    try:
        access_token_obj = refresh.access_token
        try:
            access_token_obj.outstand()
        except Exception:
            logger.exception('Failed to create OutstandingToken for newly issued access (client_login_view)')
        access_token_str = str(access_token_obj)
    except Exception:
        access_token_str = str(refresh.access_token)

    resp_body = {
        'access': access_token_str,
        'refresh': str(refresh),
        'role': frontend_role,
        'redirect_url': compute_redirect_url(request, frontend_role),
        'user': {
            'email': user.email,
            'name': f'{user.first_name} {user.last_name}'.strip() or user.username
        }
    }

    # Attach perf info in DEBUG
    if settings.DEBUG:
        resp_body['perf_ms'] = duration_ms

    response = Response(resp_body, status=status.HTTP_200_OK)
    response['X-Login-Duration-ms'] = str(duration_ms)
    
    # Set HttpOnly cookies for API and client usage using CookieManager
    try:
        access_token = resp_body.get('access')
        refresh_token = resp_body.get('refresh')
        secure_flag = not settings.DEBUG
        cookie_domain = None  # Don't set domain for client to avoid localhost issues
        
        # Use CookieManager to set cookies with auto-clear support
        try:
            tokens_dict = {
                'access': access_token,
                'refresh': refresh_token
            }
            user_data = {
                'username': user.email,
                'email': user.email,
                'role': frontend_role
            }
            
            client_ip = get_client_ip(request)
            
            response = CookieManager.set_auth_cookies(
                response=response,
                tokens_dict=tokens_dict,
                user_data=user_data,
                remember_me=remember,
                secure_flag=secure_flag,
                cookie_domain=cookie_domain,
                user_id=user.id,
                ip_address=client_ip
            )
            
            # Expose role to frontend via non-HttpOnly cookie
            response.set_cookie('role', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/', domain=cookie_domain)
            response.set_cookie('UserRole', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/', domain=cookie_domain)
            
        except Exception:
            logger.exception("Failed to set cookies using CookieManager; using fallback method")
            
            # Fallback: set cookies manually
            try:
                refresh_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('REFRESH_TOKEN_LIFETIME', None)
                access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
                refresh_max_age = int(refresh_lifetime.total_seconds()) if refresh_lifetime else None
                access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
            except Exception:
                refresh_max_age = None
                access_max_age = None

            if access_token:
                response.set_cookie('jwt_token', access_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age, domain=cookie_domain)
                response.set_cookie('access_token', access_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age, domain=cookie_domain)
                response.set_cookie('accessToken', access_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age, domain=cookie_domain)
            if refresh_token:
                response.set_cookie('refresh_token', refresh_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=refresh_max_age, domain=cookie_domain)
            
            # Expose role to frontend via non-HttpOnly cookie and legacy name `UserRole`
            try:
                response.set_cookie('role', frontend_role, httponly=False, secure=(not settings.DEBUG), samesite='Lax', path='/', domain=cookie_domain)
                response.set_cookie('UserRole', frontend_role, httponly=False, secure=(not settings.DEBUG), samesite='Lax', path='/', domain=cookie_domain)
            except Exception:
                logger.exception('Failed to set role cookies on login response')

    except Exception:
        logger.exception('Failed to set auth cookies on login response')

    # Optionally set session for non-API logins (skip for /api/ and /client/api/)
    try:
        if not (request.path.startswith('/api/') or request.path.startswith('/client/api/')):
            # Perform session writes in background to avoid blocking on slow session backends
            def _write_session():
                try:
                    request.session['user_id'] = user.id
                    request.session['user_email'] = user.email
                    request.session['user_name'] = f'{user.first_name} {user.last_name}'.strip() or user.username
                    request.session['role'] = user.manager_admin_status or 'Client'
                    if settings.DEBUG:
                        logger.debug(f"Wrote session for login (background): user={user.email}")
                except Exception as e:
                    logger.debug(f"Background session write failed: {e}")

            try:
                t = threading.Thread(target=_write_session, daemon=True)
                t.start()
            except Exception:
                # fallback to synchronous write if background thread fails
                try:
                    request.session['user_id'] = user.id
                    request.session['user_email'] = user.email
                    request.session['user_name'] = f'{user.first_name} {user.last_name}'.strip() or user.username
                    request.session['role'] = user.manager_admin_status or 'Client'
                except Exception as e:
                    logger.debug(f"Session write skipped or failed for client login: {e}")
    except Exception as e:
        logger.debug(f"Session write skipped or failed for client login: {e}")

    return response
    
    return Response({
        'error': 'Invalid credentials',
        'message': 'Please check your email and password'
    }, status=status.HTTP_401_UNAUTHORIZED)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def send_signup_otp_view(request):
    """Send an OTP for signup verification to an arbitrary email address.

    This does not require the user to exist yet. OTPs are stored in the cache
    under key `signup_otp:{email}` for a short TTL and rate-limited by IP/email.
    """
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Determine client IP and enforce per-IP send limit (default 5/hour)
        try:
            current_ip = get_client_ip(request)
        except Exception:
            current_ip = None

        otp_ip_limit = getattr(settings, 'OTP_SEND_RATE_LIMIT_PER_HOUR_PER_IP', 5)
        if current_ip:
            rl_ip_key = f"rl:signup:otp:ip:{current_ip}"
            if _check_rate_limit(rl_ip_key, otp_ip_limit, 3600):
                return Response({'error': 'Too many OTP send attempts from your IP. Try again later.'}, status=429)

        # Enforce cache-backed per-email send limit (default 5/hour)
        otp_send_limit = getattr(settings, 'OTP_SEND_RATE_LIMIT_PER_HOUR', 5)
        rl_key = f"rl:signup:otp:email:{email.strip().lower()}"
        if _check_rate_limit(rl_key, otp_send_limit, 3600):
            return Response({'error': 'Too many OTP send attempts. Try again later.'}, status=429)

        # Generate OTP and store in cache for 10 minutes
        otp = f"{random.randint(100000, 999999)}"
        cache_key = f"signup_otp:{email.strip().lower()}"
        cache.set(cache_key, otp, timeout=getattr(settings, 'SIGNUP_OTP_TTL_SECONDS', 600))

        # Send OTP email (best-effort)
        try:
            EmailSender.send_otp_email(email, otp)
        except Exception:
            logger.exception('Failed to send signup OTP email')

        return Response({'message': 'Verification code sent to your email.'})
    except Exception:
        logger.exception('send_signup_otp_view failed')
        return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_signup_otp_view(request):
    """Verify a signup OTP stored in cache for the provided email."""
    email = request.data.get('email')
    otp = request.data.get('otp')
    if not email or not otp:
        return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        cache_key = f"signup_otp:{email.strip().lower()}"
        expected = cache.get(cache_key)
        if not expected:
            return Response({'error': 'No OTP found or it has expired'}, status=status.HTTP_400_BAD_REQUEST)
        if expected != str(otp).strip():
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        # OTP verified: remove from cache and mark ephemeral verified flag (short TTL)
        cache.delete(cache_key)
        verified_key = f"signup_verified:{email.strip().lower()}"
        cache.set(verified_key, True, timeout=getattr(settings, 'SIGNUP_VERIFIED_TTL_SECONDS', 600))
        return Response({'verified': True})
    except Exception:
        logger.exception('verify_signup_otp_view failed')
        return Response({'error': 'OTP verification failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def set_token_view(request):
    key = request.data.get('key')
    value = request.data.get('value')
    remember = request.data.get('remember', False)
    if not key:
        return Response({'error': 'key is required'}, status=status.HTTP_400_BAD_REQUEST)

    allowed = {'jwt_token', 'access_token', 'accessToken', 'refreshToken', 'refresh_token', 'token'}
    if key not in allowed:
        return Response({'error': 'unsupported key'}, status=status.HTTP_400_BAD_REQUEST)

    secure_flag = not settings.DEBUG
    try:
        # choose lifetime
        try:
            refresh_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('REFRESH_TOKEN_LIFETIME', None)
            access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
            refresh_max_age = int(refresh_lifetime.total_seconds()) if refresh_lifetime else None
            access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
        except Exception:
            refresh_max_age = None
            access_max_age = None

        max_age = refresh_max_age if 'refresh' in key else access_max_age
        resp = Response({'status': 'ok'})
        resp.set_cookie(key, value, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=max_age)
        return resp
    except Exception as e:
        logger.exception('set_token_view failed')
        return Response({'error': 'failed to set cookie'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _save_profile_image_from_url(user, url):
    try:
        if not url:
            return
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return
        content = resp.content
        # Attempt to derive extension
        parsed = urlparse(url)
        root, ext = os.path.splitext(parsed.path)
        if not ext:
            # Try from content-type
            ctype = resp.headers.get('content-type', '')
            if 'jpeg' in ctype or 'jpg' in ctype:
                ext = '.jpg'
            elif 'png' in ctype:
                ext = '.png'
            else:
                ext = '.jpg'

        filename = f"{(user.email or 'user')}_profile{ext}"
        user.profile_pic.save(filename, ContentFile(content), save=True)
    except Exception:
        logger.exception('Failed to save profile image from url')


def _verify_id_token(id_token, provider, client_id, tenant=None):
    """Verify an ID token (Google or Microsoft) against provider JWKS and return decoded claims on success.

    Returns decoded claims dict or None on failure.
    """
    try:
        if not id_token:
            return None
        if provider == 'google':
            jwks_url = 'https://www.googleapis.com/oauth2/v3/certs'
            issuer = 'https://accounts.google.com'
        elif provider == 'microsoft':
            t = tenant or 'common'
            jwks_url = f'https://login.microsoftonline.com/{t}/discovery/v2.0/keys'
            issuer = f'https://login.microsoftonline.com/{t}/v2.0'
        else:
            return None

        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token).key
        decoded = jwt.decode(id_token, signing_key, algorithms=['RS256'], audience=client_id, issuer=issuer)
        return decoded
    except Exception:
        logger.exception('ID token verification failed')
        return None


@csrf_exempt
@api_view(['GET', 'POST', 'OPTIONS'])
@permission_classes([AllowAny])
def google_oauth_view(request):
    """Exchange Google id_token or access_token for user signup/login.

    Accepts: { id_token?, access_token?, profile?: {name,email,phone_number,dob,address,profile_image_url}, referral_code? }
    """
    # Support GET to initiate OAuth redirect from frontend
    if request.method == 'GET':
        try:
            client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', None) or os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
            if not client_id:
                return Response({'error': 'Google OAuth not configured'}, status=status.HTTP_400_BAD_REQUEST)
            # server callback URI for authorization-code flow
            callback_path = reverse('api:api-oauth-google-callback')
            redirect_uri = request.build_absolute_uri(callback_path)
            # preserve requested action in state
            state_val = request.GET.get('state') or request.GET.get('action') or 'login'
            # generate CSRF-like nonce and store in session keyed by provider
            try:
                nonce = secrets.token_urlsafe(16)
                request.session['oauth_state_nonce_google'] = nonce
                request.session.modified = True
            except Exception:
                nonce = None
            # embed action and nonce into state (frontend sends action only; server appends nonce)
            params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': 'openid email profile',
                'access_type': 'offline',
                'prompt': 'select_account'
            }
            if state_val:
                if nonce:
                    params['state'] = f"{state_val}:{nonce}"
                else:
                    params['state'] = state_val
            auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)
            return HttpResponseRedirect(auth_url)
        except Exception:
            logger.exception('Failed to build Google OAuth redirect')
            return Response({'error': 'Failed to initiate Google OAuth'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['X-CSRFToken'] = get_token(request)
        return response

    data = request.data
    id_token = data.get('id_token')
    access_token = data.get('access_token')
    profile = data.get('profile', {}) or {}
    referral_code = data.get('referral_code')

    user_info = {}
    try:
        if id_token:
            # Verify ID token signature, aud and iss
            client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', None) or os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
            verified = _verify_id_token(id_token, 'google', client_id)
            if not verified:
                return Response({'error': 'Invalid Google id_token'}, status=status.HTTP_400_BAD_REQUEST)
            user_info = verified
        elif access_token:
            # Use userinfo endpoint
            r = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
            if r.status_code != 200:
                return Response({'error': 'Invalid Google access_token'}, status=status.HTTP_400_BAD_REQUEST)
            user_info = r.json()
        else:
            # Allow frontend to provide profile directly
            user_info = profile

        email = user_info.get('email') or profile.get('email')
        if not email:
            return Response({'error': 'Email not provided by Google'}, status=status.HTTP_400_BAD_REQUEST)

        name = user_info.get('name') or profile.get('name') or ''
        first_name = ''
        last_name = ''
        if name:
            parts = name.split(maxsplit=1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ''

        phone_number = user_info.get('phone_number') or profile.get('phone_number') or ''
        dob = user_info.get('birthdate') or profile.get('dob')
        address = profile.get('address') or ''
        picture = user_info.get('picture') or profile.get('profile_image_url')

        # Find or create user
        user = CustomUser.objects.filter(email__iexact=email).first()
        created = False
        if not user:
            # Create with random password
            password = CustomUser.objects.make_random_password()
            user = CustomUser.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name or email.split('@')[0],
                last_name=last_name or '',
                manager_admin_status='Client',
                parent_ib=CustomUser.objects.filter(referral_code=referral_code, IB_status=True).first() if referral_code else None,
                referral_code_used=referral_code if referral_code else None
            )
            created = True

        # Update fields if provided
        updated_fields = []
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            updated_fields.append('first_name')
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            updated_fields.append('last_name')
        if phone_number and user.phone_number != phone_number:
            user.phone_number = phone_number
            updated_fields.append('phone_number')
        if dob:
            try:
                # Accept YYYY-MM-DD or other ISO formats
                parsed = datetime.fromisoformat(dob).date() if isinstance(dob, str) else dob
                if user.dob != parsed:
                    user.dob = parsed
                    updated_fields.append('dob')
            except Exception:
                pass
        if address and user.address != address:
            user.address = address
            updated_fields.append('address')

        if picture:
            try:
                _save_profile_image_from_url(user, picture)
            except Exception:
                pass

        if updated_fields and not created:
            try:
                user.save(update_fields=updated_fields)
            except Exception:
                user.save()

        # Auto-login: issue JWTs
        try:
            refresh = RefreshToken.for_user(user)
            try:
                refresh['aud'] = 'client.vtindex'
                refresh['scope'] = 'client:*'
                access = refresh.access_token
                access['aud'] = 'client.vtindex'
                access['scope'] = 'client:*'
            except Exception:
                access = refresh.access_token
            try:
                access.outstand()
            except Exception:
                logger.exception('Failed to create OutstandingToken for oauth access')
            access_token = str(access)
        except Exception:
            return Response({'error': 'Failed to create session tokens'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        resp_body = {
            'success': True,
            'created': created,
            'access': access_token,
            'refresh': str(refresh),
            'role': 'client',
            'user': {
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip(),
                'phone_number': user.phone_number,
                'dob': user.dob.isoformat() if user.dob else None,
                'address': user.address,
            }
        }

        response = Response(resp_body)
        # Set cookies similar to signup flow
        try:
            secure_flag = not settings.DEBUG
            access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
            access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
            response.set_cookie('jwt_token', access_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
            response.set_cookie('access_token', access_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
            response.set_cookie('refresh_token', str(refresh), httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=None)
            response.set_cookie('role', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')
            response.set_cookie('UserRole', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')
        except Exception:
            logger.exception('Failed to set auth cookies for google oauth')

        return response
    except Exception:
        logger.exception('google_oauth_view failed')
        return Response({'error': 'Google OAuth signup failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['GET', 'POST', 'OPTIONS'])
@permission_classes([AllowAny])
def microsoft_oauth_view(request):
    """Exchange Microsoft access_token for user signup/login.

    Accepts: { access_token?, profile?: {name,email,phone_number,dob,address,profile_image_url}, referral_code? }
    """
    # Support GET to initiate Microsoft OAuth redirect from frontend
    if request.method == 'GET':
        try:
            client_id = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', None) or os.environ.get('MICROSOFT_OAUTH_CLIENT_ID')
            tenant = getattr(settings, 'MICROSOFT_OAUTH_TENANT_ID', None) or os.environ.get('MICROSOFT_OAUTH_TENANT_ID') or 'common'
            if not client_id:
                return Response({'error': 'Microsoft OAuth not configured'}, status=status.HTTP_400_BAD_REQUEST)
            # server callback URI for authorization-code flow
            callback_path = reverse('api:api-oauth-microsoft-callback')
            redirect_uri = request.build_absolute_uri(callback_path)
            state_val = request.GET.get('state') or request.GET.get('action') or 'login'
            try:
                nonce = secrets.token_urlsafe(16)
                request.session['oauth_state_nonce_microsoft'] = nonce
                request.session.modified = True
            except Exception:
                nonce = None
            params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': 'openid email profile',
                'response_mode': 'query',
                'prompt': 'select_account'
            }
            if state_val:
                if nonce:
                    params['state'] = f"{state_val}:{nonce}"
                else:
                    params['state'] = state_val
            auth_url = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?' + urlencode(params)
            return HttpResponseRedirect(auth_url)
        except Exception:
            logger.exception('Failed to build Microsoft OAuth redirect')
            return Response({'error': 'Failed to initiate Microsoft OAuth'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['X-CSRFToken'] = get_token(request)
        return response

    data = request.data
    access_token = data.get('access_token')
    id_token = data.get('id_token')
    profile = data.get('profile', {}) or {}
    referral_code = data.get('referral_code')

    user_info = {}
    try:
        if id_token:
            client_id = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', None) or os.environ.get('MICROSOFT_OAUTH_CLIENT_ID')
            tenant = getattr(settings, 'MICROSOFT_OAUTH_TENANT_ID', None) or os.environ.get('MICROSOFT_OAUTH_TENANT_ID') or 'common'
            verified = _verify_id_token(id_token, 'microsoft', client_id, tenant=tenant)
            if not verified:
                return Response({'error': 'Invalid Microsoft id_token'}, status=status.HTTP_400_BAD_REQUEST)
            # Map claims to expected fields
            user_info = verified
            photo_bytes = None
        elif access_token:
            headers = {'Authorization': f'Bearer {access_token}'}
            r = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=10)
            if r.status_code != 200:
                return Response({'error': 'Invalid Microsoft access_token'}, status=status.HTTP_400_BAD_REQUEST)
            user_info = r.json()
            # Try to fetch photo
            photo_url = None
            try:
                pr = requests.get('https://graph.microsoft.com/v1.0/me/photo/$value', headers=headers, timeout=10)
                if pr.status_code == 200:
                    # Save directly from bytes
                    # We'll attach to user later via helper
                    photo_bytes = pr.content
                else:
                    photo_bytes = None
            except Exception:
                photo_bytes = None
        else:
            user_info = profile
            photo_bytes = None

        email = user_info.get('mail') or user_info.get('userPrincipalName') or profile.get('email')
        if not email:
            return Response({'error': 'Email not provided by Microsoft'}, status=status.HTTP_400_BAD_REQUEST)

        name = user_info.get('displayName') or profile.get('name') or ''
        parts = name.split(maxsplit=1) if name else []
        first_name = parts[0] if parts else email.split('@')[0]
        last_name = parts[1] if len(parts) > 1 else ''

        phone_number = profile.get('phone_number') or ''
        dob = profile.get('dob')
        address = profile.get('address') or ''

        user = CustomUser.objects.filter(email__iexact=email).first()
        created = False
        if not user:
            password = CustomUser.objects.make_random_password()
            user = CustomUser.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                manager_admin_status='Client',
                parent_ib=CustomUser.objects.filter(referral_code=referral_code, IB_status=True).first() if referral_code else None,
                referral_code_used=referral_code if referral_code else None
            )
            created = True

        updated_fields = []
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            updated_fields.append('first_name')
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            updated_fields.append('last_name')
        if phone_number and user.phone_number != phone_number:
            user.phone_number = phone_number
            updated_fields.append('phone_number')
        if dob:
            try:
                parsed = datetime.fromisoformat(dob).date() if isinstance(dob, str) else dob
                if user.dob != parsed:
                    user.dob = parsed
                    updated_fields.append('dob')
            except Exception:
                pass
        if address and user.address != address:
            user.address = address
            updated_fields.append('address')

        if photo_bytes:
            try:
                ext = '.jpg'
                filename = f"{(user.email or 'user')}_profile{ext}"
                user.profile_pic.save(filename, ContentFile(photo_bytes), save=True)
            except Exception:
                logger.exception('Failed to save microsoft profile photo')

        if updated_fields and not created:
            try:
                user.save(update_fields=updated_fields)
            except Exception:
                user.save()

        # Issue tokens
        try:
            refresh = RefreshToken.for_user(user)
            try:
                refresh['aud'] = 'client.vtindex'
                refresh['scope'] = 'client:*'
                access = refresh.access_token
                access['aud'] = 'client.vtindex'
                access['scope'] = 'client:*'
            except Exception:
                access = refresh.access_token
            try:
                access.outstand()
            except Exception:
                logger.exception('Failed to create OutstandingToken for oauth access')
            access_token = str(access)
        except Exception:
            return Response({'error': 'Failed to create session tokens'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        resp_body = {
            'success': True,
            'created': created,
            'access': access_token,
            'refresh': str(refresh),
            'role': 'client',
            'user': {
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip(),
                'phone_number': user.phone_number,
                'dob': user.dob.isoformat() if user.dob else None,
                'address': user.address,
            }
        }

        response = Response(resp_body)
        try:
            secure_flag = not settings.DEBUG
            access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
            access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
            response.set_cookie('jwt_token', access_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
            response.set_cookie('access_token', access_token, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
            response.set_cookie('refresh_token', str(refresh), httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=None)
            response.set_cookie('role', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')
            response.set_cookie('UserRole', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')
        except Exception:
            logger.exception('Failed to set auth cookies for microsoft oauth')

        return response
    except Exception:
        logger.exception('microsoft_oauth_view failed')
        return Response({'error': 'Microsoft OAuth signup failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def google_oauth_callback(request):
    """Server-side callback to handle Google authorization-code exchange."""
    code = request.GET.get('code')
    if not code:
        return Response({'error': 'Missing code'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', None) or os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
        client_secret = getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', None) or os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')
        if not client_id or not client_secret:
            return Response({'error': 'Google OAuth not configured'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate state nonce (CSRF-like)
        state_raw = request.GET.get('state') or ''
        try:
            action = None
            if ':' in state_raw:
                action, nonce = state_raw.rsplit(':', 1)
            else:
                action = state_raw
                nonce = None
            session_nonce = request.session.get('oauth_state_nonce_google')
            # If we have a session nonce, require it to match
            if session_nonce:
                if not nonce or nonce != session_nonce:
                    logger.warning('OAuth state nonce mismatch for Google')
                    return Response({'error': 'Invalid oauth state'}, status=status.HTTP_400_BAD_REQUEST)
                # consume nonce
                try:
                    del request.session['oauth_state_nonce_google']
                    request.session.modified = True
                except Exception:
                    pass
        except Exception:
            logger.exception('Failed to validate oauth state for Google')
            return Response({'error': 'Invalid oauth state'}, status=status.HTTP_400_BAD_REQUEST)

        redirect_uri = request.build_absolute_uri()
        token_url = 'https://oauth2.googleapis.com/token'
        data = {
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        r = requests.post(token_url, data=data, headers=headers, timeout=10)
        if r.status_code != 200:
            logger.exception('Google token exchange failed: %s', r.text)
            return Response({'error': 'Failed to exchange code for token'}, status=status.HTTP_400_BAD_REQUEST)
        token_json = r.json()
        access_token = token_json.get('access_token')
        id_token = token_json.get('id_token')
        if not access_token:
            return Response({'error': 'No access_token from Google'}, status=status.HTTP_400_BAD_REQUEST)
        # Prefer ID token claims if present and valid; otherwise fetch userinfo
        user_info = None
        if id_token:
            verified = _verify_id_token(id_token, 'google', client_id)
            if not verified:
                logger.exception('Google id_token verification failed')
                return Response({'error': 'Failed to verify id_token'}, status=status.HTTP_400_BAD_REQUEST)
            user_info = verified
        if not user_info:
            ui = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
            if ui.status_code != 200:
                logger.exception('Failed to fetch Google userinfo: %s', ui.text)
                return Response({'error': 'Failed to fetch userinfo'}, status=status.HTTP_400_BAD_REQUEST)
            user_info = ui.json()

        email = user_info.get('email')
        # Respect state: if client requested login and user doesn't exist, redirect to signup page
        state = (request.GET.get('state') or '').lower()
        frontend_base = getattr(settings, 'FRONTEND_BASE_URL', None) or os.environ.get('FRONTEND_BASE_URL') or 'http://localhost:3000'
        if state == 'login' and not CustomUser.objects.filter(email__iexact=email).exists():
            # Redirect user to frontend registration flow with prefilled email
            redirect_to = frontend_base.rstrip('/') + '/register/?' + urlencode({'email': email})
            return HttpResponseRedirect(redirect_to)
        name = user_info.get('name') or ''
        picture = user_info.get('picture')
        parts = name.split(maxsplit=1) if name else []
        first_name = parts[0] if parts else email.split('@')[0]
        last_name = parts[1] if len(parts) > 1 else ''

        user = CustomUser.objects.filter(email__iexact=email).first()
        created = False
        if not user:
            password = CustomUser.objects.make_random_password()
            user = CustomUser.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                manager_admin_status='Client'
            )
            created = True

        # update picture
        if picture:
            try:
                _save_profile_image_from_url(user, picture)
            except Exception:
                logger.exception('Failed to save google profile image')

        # Update last-login info and log activity
        try:
            user.last_login_at = timezone.now()
            user.last_login_ip = get_client_ip(request)
            user.save(update_fields=['last_login_at', 'last_login_ip'])
        except Exception:
            logger.exception('Failed to update last_login info for google oauth')

        try:
            ActivityLog.objects.create(
                user=user,
                activity="User login via Google OAuth",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="login",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now(),
                related_object_id=user.id,
                related_object_type="OAuthLogin"
            )
        except Exception:
            logger.exception('Failed to create ActivityLog for Google OAuth login')

        # Issue tokens and set cookies, then redirect to frontend
        refresh = RefreshToken.for_user(user)
        try:
            refresh['aud'] = 'client.vtindex'
            refresh['scope'] = 'client:*'
            access = refresh.access_token
            access['aud'] = 'client.vtindex'
            access['scope'] = 'client:*'
        except Exception:
            access = refresh.access_token

        access_token_str = str(access)
        frontend_base = getattr(settings, 'FRONTEND_BASE_URL', None) or os.environ.get('FRONTEND_BASE_URL') or 'http://localhost:3000'
        redirect_to = frontend_base.rstrip('/') + '/dashboard/'

        resp = HttpResponseRedirect(redirect_to)
        secure_flag = not settings.DEBUG
        try:
            access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
            access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
        except Exception:
            access_max_age = None

        resp.set_cookie('jwt_token', access_token_str, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
        resp.set_cookie('access_token', access_token_str, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
        resp.set_cookie('refresh_token', str(refresh), httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=None)
        resp.set_cookie('role', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')
        resp.set_cookie('UserRole', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')

        return resp
    except Exception:
        logger.exception('google_oauth_callback failed')
        return Response({'error': 'Google oauth callback failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def microsoft_oauth_callback(request):
    """Server-side callback to handle Microsoft authorization-code exchange."""
    code = request.GET.get('code')
    if not code:
        return Response({'error': 'Missing code'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        client_id = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', None) or os.environ.get('MICROSOFT_OAUTH_CLIENT_ID')
        client_secret = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_SECRET', None) or os.environ.get('MICROSOFT_OAUTH_CLIENT_SECRET')
        tenant = getattr(settings, 'MICROSOFT_OAUTH_TENANT_ID', None) or os.environ.get('MICROSOFT_OAUTH_TENANT_ID') or 'common'
        if not client_id or not client_secret:
            return Response({'error': 'Microsoft OAuth not configured'}, status=status.HTTP_400_BAD_REQUEST)

        redirect_uri = request.build_absolute_uri()
        token_url = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        r = requests.post(token_url, data=data, headers=headers, timeout=10)
        if r.status_code != 200:
            logger.exception('Microsoft token exchange failed: %s', r.text)
            return Response({'error': 'Failed to exchange code for token'}, status=status.HTTP_400_BAD_REQUEST)
        token_json = r.json()
        access_token = token_json.get('access_token')
        id_token = token_json.get('id_token')
        if not access_token and not id_token:
            return Response({'error': 'No access_token from Microsoft'}, status=status.HTTP_400_BAD_REQUEST)

        # If id_token present, verify and prefer its claims; otherwise we'll fetch Graph
        user_info = None
        if id_token:
            verified = _verify_id_token(id_token, 'microsoft', client_id, tenant=tenant)
            if verified:
                user_info = verified

        # Validate state nonce (CSRF-like)
        state_raw = request.GET.get('state') or ''
        try:
            action = None
            if ':' in state_raw:
                action, nonce = state_raw.rsplit(':', 1)
            else:
                action = state_raw
                nonce = None
            session_nonce = request.session.get('oauth_state_nonce_microsoft')
            if session_nonce:
                if not nonce or nonce != session_nonce:
                    logger.warning('OAuth state nonce mismatch for Microsoft')
                    return Response({'error': 'Invalid oauth state'}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    del request.session['oauth_state_nonce_microsoft']
                    request.session.modified = True
                except Exception:
                    pass
        except Exception:
            logger.exception('Failed to validate oauth state for Microsoft')
            return Response({'error': 'Invalid oauth state'}, status=status.HTTP_400_BAD_REQUEST)

        # fetch userinfo only if id_token didn't provide claims
        if not user_info:
            ui = requests.get('https://graph.microsoft.com/v1.0/me', headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
            if ui.status_code != 200:
                logger.exception('Failed to fetch Microsoft userinfo: %s', ui.text)
                return Response({'error': 'Failed to fetch userinfo'}, status=status.HTTP_400_BAD_REQUEST)
            user_info = ui.json()

        email = user_info.get('mail') or user_info.get('userPrincipalName')
        # Respect state: if client requested login and user doesn't exist, redirect to signup page
        state = (request.GET.get('state') or '').lower()
        frontend_base = getattr(settings, 'FRONTEND_BASE_URL', None) or os.environ.get('FRONTEND_BASE_URL') or 'http://localhost:3000'
        if state == 'login' and not CustomUser.objects.filter(email__iexact=email).exists():
            redirect_to = frontend_base.rstrip('/') + '/register/?' + urlencode({'email': email})
            return HttpResponseRedirect(redirect_to)
        name = user_info.get('displayName') or ''
        parts = name.split(maxsplit=1) if name else []
        first_name = parts[0] if parts else email.split('@')[0]
        last_name = parts[1] if len(parts) > 1 else ''

        user = CustomUser.objects.filter(email__iexact=email).first()
        created = False
        if not user:
            password = CustomUser.objects.make_random_password()
            user = CustomUser.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                manager_admin_status='Client'
            )
            created = True

        # Update last-login info and log activity
        try:
            user.last_login_at = timezone.now()
            user.last_login_ip = get_client_ip(request)
            user.save(update_fields=['last_login_at', 'last_login_ip'])
        except Exception:
            logger.exception('Failed to update last_login info for microsoft oauth')

        try:
            ActivityLog.objects.create(
                user=user,
                activity="User login via Microsoft OAuth",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="login",
                activity_category="client",
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now(),
                related_object_id=user.id,
                related_object_type="OAuthLogin"
            )
        except Exception:
            logger.exception('Failed to create ActivityLog for Microsoft OAuth login')

        # Issue tokens and set cookies, then redirect to frontend
        refresh = RefreshToken.for_user(user)
        try:
            refresh['aud'] = 'client.vtindex'
            refresh['scope'] = 'client:*'
            access = refresh.access_token
            access['aud'] = 'client.vtindex'
            access['scope'] = 'client:*'
        except Exception:
            access = refresh.access_token

        access_token_str = str(access)
        frontend_base = getattr(settings, 'FRONTEND_BASE_URL', None) or os.environ.get('FRONTEND_BASE_URL') or 'http://localhost:3000'
        redirect_to = frontend_base.rstrip('/') + '/dashboard/'

        resp = HttpResponseRedirect(redirect_to)
        secure_flag = not settings.DEBUG
        try:
            access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
            access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
        except Exception:
            access_max_age = None

        resp.set_cookie('jwt_token', access_token_str, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
        resp.set_cookie('access_token', access_token_str, httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=access_max_age)
        resp.set_cookie('refresh_token', str(refresh), httponly=True, secure=secure_flag, samesite='Strict', path='/', max_age=None)
        resp.set_cookie('role', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')
        resp.set_cookie('UserRole', 'client', httponly=False, secure=secure_flag, samesite='Lax', path='/')

        return resp
    except Exception:
        logger.exception('microsoft_oauth_callback failed')
        return Response({'error': 'Microsoft oauth callback failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def clear_token_view(request):
    key = request.data.get('key')
    if not key:
        return Response({'error': 'key is required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        resp = Response({'status': 'ok'})
        # clear cookie by setting max_age=0
        resp.set_cookie(key, '', httponly=True, secure=(not settings.DEBUG), samesite='Strict', path='/', max_age=0)
        return resp
    except Exception:
        logger.exception('clear_token_view failed')
        return Response({'error': 'failed to clear cookie'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def resend_login_otp_view(request):
    """Endpoint to resend a login OTP for a pending login verification. Enforces a short cooldown to prevent abuse."""
    email = request.data.get('email')
    if not email:
        try:
            ActivityLog.objects.create(
                user=None,
                activity="OTP resend attempt - missing email",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=400,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to log OTP resend missing email")
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = CustomUser.objects.get(email=email)

        # Determine client IP and enforce per-IP send limit (default 5/hour)
        try:
            current_ip = get_client_ip(request)
        except Exception:
            current_ip = None

        otp_ip_limit = getattr(settings, 'OTP_SEND_RATE_LIMIT_PER_HOUR_PER_IP', 5)
        if current_ip:
            rl_ip_key = f"rl:otp:send:ip:{current_ip}"
            if _check_rate_limit(rl_ip_key, otp_ip_limit, 3600):
                return Response({'error': 'Too many OTP send attempts from your IP. Try again later.'}, status=429)

        # If a login OTP exists and was created recently, enforce a cooldown (e.g., 60s)
        cooldown_seconds = getattr(settings, 'LOGIN_OTP_RESEND_COOLDOWN', 60)
        if user.login_otp_created_at:
            elapsed = (timezone.now() - user.login_otp_created_at).total_seconds()
            if elapsed < cooldown_seconds:
                return Response({'error': 'Please wait before requesting another code.', 'retry_after': int(cooldown_seconds - elapsed)}, status=429)

        # Also enforce cache-backed per-email resend/send limit (default 5/hour)
        otp_send_limit = getattr(settings, 'OTP_SEND_RATE_LIMIT_PER_HOUR', 5)
        rl_key = f"rl:otp:send:email:{email.strip().lower()}"
        if _check_rate_limit(rl_key, otp_send_limit, 3600):
            return Response({'error': 'Too many OTP send attempts. Try again later.'}, status=429)

        # Generate new login OTP
        otp = f"{random.randint(100000, 999999)}"
        # Hash OTP before storing (same as initial login)
        from adminPanel.views.auth_views import hash_otp
        hashed_otp = hash_otp(otp)
        user.login_otp = hashed_otp
        user.login_otp_created_at = timezone.now()
        user.save(update_fields=['login_otp', 'login_otp_created_at'])

        # Send login OTP email using the dedicated login template (plain text)
        try:
            EmailSender.send_login_otp_email(
                user.email,
                otp,
                ip_address=get_client_ip(request),
                login_time=timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                first_name=user.first_name
            )
        except Exception:
            logger.exception('Failed to send login OTP email on resend')

        # Log resend activity
        try:
            ActivityLog.objects.create(
                user=user,
                activity="Login OTP resent",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="update",
                activity_category="client",
                status_code=200,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now(),
                related_object_id=user.id,
                related_object_type="LoginVerification"
            )
        except Exception:
            logger.exception('Failed to create ActivityLog for OTP resend')

        otp_ttl_seconds = getattr(settings, 'LOGIN_OTP_TTL_SECONDS', 60)
        return Response({
            'message': 'Verification code resent to your email.',
            'retry_after': int(cooldown_seconds),
            'otp_expires_in': int(otp_ttl_seconds)
        })
    except CustomUser.DoesNotExist:
        try:
            ActivityLog.objects.create(
                user=None,
                activity=f"OTP resend attempt - user not found: {email}",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=404,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to log OTP resend user not found")
        return Response({'error': 'No account found with this email'}, status=status.HTTP_404_NOT_FOUND)


@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def login_otp_status_view(request):
    """Return remaining cooldown and OTP expiry for a pending login OTP for the given email.

    Query params: email
    Response: { has_pending: bool, retry_after: int_seconds, otp_expires_in: int_seconds }
    """
    email = request.query_params.get('email')
    if not email:
        try:
            ActivityLog.objects.create(
                user=None,
                activity="OTP status check - missing email",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=400,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to log OTP status missing email")
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        user = CustomUser.objects.get(email=email)
        now = timezone.now()
        has_pending = bool(user.login_otp and user.login_otp_created_at)
        cooldown_seconds = getattr(settings, 'LOGIN_OTP_RESEND_COOLDOWN', 60)
        otp_ttl_seconds = getattr(settings, 'LOGIN_OTP_TTL_SECONDS', 60)

        retry_after = 0
        otp_expires_in = 0
        if user.login_otp_created_at:
            elapsed = (now - user.login_otp_created_at).total_seconds()
            if elapsed < cooldown_seconds:
                retry_after = int(cooldown_seconds - elapsed)
            if elapsed < otp_ttl_seconds:
                otp_expires_in = int(otp_ttl_seconds - elapsed)

        # Log successful status check
        try:
            ActivityLog.objects.create(
                user=user,
                activity="OTP status checked",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=200,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now(),
                related_object_id=user.id,
                related_object_type="LoginVerification"
            )
        except Exception:
            logger.exception("Failed to log OTP status check")

        return Response({
            'has_pending': has_pending,
            'retry_after': retry_after,
            'otp_expires_in': otp_expires_in
        })
    except CustomUser.DoesNotExist:
        try:
            ActivityLog.objects.create(
                user=None,
                activity=f"OTP status check - user not found: {email}",
                ip_address=get_client_ip(request),
                endpoint=request.path,
                activity_type="create",
                activity_category="client",
                status_code=404,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                timestamp=timezone.now()
            )
        except Exception:
            logger.exception("Failed to log OTP status user not found")
        return Response({'error': 'No account found with this email'}, status=status.HTTP_404_NOT_FOUND)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_view(request):
    email = request.data.get('email')
    
    if not email:
        return Response({
            'error': 'Email is required'
        }, status=status.HTTP_400_BAD_REQUEST)
        
    try:
        user = CustomUser.objects.get(email=email)
        # Generate password reset token
        token = default_token_generator.make_token(user)
        # Build reset link (assume frontend route /reset-password/)
        base_url = getattr(settings, 'FRONTEND_BASE_URL', 'https://client.localhost')
        reset_link = f"{base_url}/reset-password/?uid={user.pk}&token={token}"
        # Send email
        EmailSender.send_password_reset_email(user.email, reset_link)
        return Response({
            'message': 'Password reset instructions have been sent to your email'
        })
    except CustomUser.DoesNotExist:
        return Response({
            'error': 'No account found with this email'
        }, status=status.HTTP_404_NOT_FOUND)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def confirm_reset_password_view(request):
    email = request.data.get('email')
    new_password = request.data.get('new_password')
    
    if not email or not new_password:
        return Response({'error': 'Email and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = CustomUser.objects.get(email=email)
        
        # For OTP-based reset, we don't need token validation since OTP was already verified
        # Just reset the password and clear OTP using hash+salt format
        hashed_password = hash_password(new_password)
        user.password = hashed_password
        user.otp = None
        user.otp_created_at = None
        user.save()
        
        return Response({'message': 'Password reset successful.'})
    except CustomUser.DoesNotExist:
        return Response({'error': 'Invalid user.'}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def send_reset_otp_view(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        user = CustomUser.objects.get(email=email)
        # Determine client IP and enforce per-IP send limit (default 5/hour)
        try:
            current_ip = get_client_ip(request)
        except Exception:
            current_ip = None

        otp_ip_limit = getattr(settings, 'OTP_SEND_RATE_LIMIT_PER_HOUR_PER_IP', 5)
        if current_ip:
            rl_ip_key = f"rl:otp:send:ip:{current_ip}"
            if _check_rate_limit(rl_ip_key, otp_ip_limit, 3600):
                return Response({'error': 'Too many OTP send attempts from your IP. Try again later.'}, status=429)

        # Enforce cache-backed per-email send limit (default 5/hour)
        otp_send_limit = getattr(settings, 'OTP_SEND_RATE_LIMIT_PER_HOUR', 5)
        rl_key = f"rl:otp:send:email:{email.strip().lower()}"
        if _check_rate_limit(rl_key, otp_send_limit, 3600):
            return Response({'error': 'Too many OTP send attempts. Try again later.'}, status=429)
        # Generate OTP
        otp = f"{random.randint(100000, 999999)}"
        # Hash OTP before storing
        hashed_otp = hash_otp(otp)
        user.otp = hashed_otp
        user.otp_created_at = timezone.now()
        user.save()
        # Send OTP email (plain text)
        EmailSender.send_otp_email(user.email, otp)
        return Response({'message': 'OTP sent to your email.'})
    except CustomUser.DoesNotExist:
        return Response({'error': 'No account found with this email'}, status=status.HTTP_404_NOT_FOUND)

class VerifyOtpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            try:
                ActivityLog.objects.create(
                    user=None,
                    activity="OTP verification attempt - missing email or OTP",
                    ip_address=get_client_ip(request),
                    endpoint=request.path,
                    activity_type="create",
                    activity_category="client",
                    status_code=400,
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    timestamp=timezone.now()
                )
            except Exception:
                logger.exception("Failed to log OTP verification missing fields")
            return Response(
                {'error': 'Email and OTP are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Enforce per-user OTP verification rate limit (default 5/hour)
        otp_limit = getattr(settings, 'OTP_VERIFY_RATE_LIMIT_PER_HOUR', 5)
        try:
            rl_key = f"rl:otp:email:{email.strip().lower()}"
        except Exception:
            rl_key = None
        if rl_key and _check_rate_limit(rl_key, otp_limit, 3600):
            return Response({'error': 'Too many OTP verification attempts. Try again later.'}, status=429)

        try:
            user = CustomUser.objects.get(email=email)

            # ============================================================
            # LOGIN OTP FLOW (New-IP / Login Verification)
            # ============================================================
            if user.login_otp:
                otp_ttl_seconds = getattr(settings, 'LOGIN_OTP_TTL_SECONDS', 60)

                if (
                    user.login_otp_created_at and
                    (timezone.now() - user.login_otp_created_at).total_seconds() > otp_ttl_seconds
                ):
                    user.login_otp = None
                    user.login_otp_created_at = None
                    user.save(update_fields=['login_otp', 'login_otp_created_at'])

                    try:
                        ActivityLog.objects.create(
                            user=user,
                            activity="OTP verification attempt - OTP expired",
                            ip_address=get_client_ip(request),
                            endpoint=request.path,
                            activity_type="create",
                            activity_category="client",
                            status_code=400,
                            user_agent=request.META.get("HTTP_USER_AGENT", ""),
                            timestamp=timezone.now(),
                            related_object_id=user.id,
                            related_object_type="LoginVerification"
                        )
                    except Exception:
                        logger.exception("Failed to log OTP expired")

                    return Response(
                        {'error': 'OTP has expired. Please request a new one.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Verify OTP against stored hash
                if not user.is_login_otp_valid(otp):
                    # Generate and send a new login OTP on invalid attempt
                    try:
                        new_otp = f"{random.randint(100000, 999999)}"
                        # Hash the new OTP before storing
                        from adminPanel.views.auth_views import hash_otp
                        hashed_otp = hash_otp(new_otp)
                        user.login_otp = hashed_otp
                        user.login_otp_created_at = timezone.now()
                        user.save(update_fields=['login_otp', 'login_otp_created_at'])
                        try:
                            EmailSender.send_login_otp_email(
                                user.email,
                                new_otp,
                                ip_address=get_client_ip(request),
                                login_time=timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                                first_name=user.first_name
                            )
                        except Exception:
                            logger.exception('Failed to send regenerated login OTP email')
                        try:
                            ActivityLog.objects.create(
                                user=user,
                                activity="Login OTP regenerated after invalid attempt",
                                ip_address=get_client_ip(request),
                                endpoint=request.path,
                                activity_type="update",
                                activity_category="client",
                                status_code=400,
                                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                                timestamp=timezone.now(),
                                related_object_id=user.id,
                                related_object_type="LoginVerification"
                            )
                        except Exception:
                            logger.exception('Failed to create ActivityLog for regenerated login OTP')
                    except Exception:
                        logger.exception('Failed to regenerate login OTP on invalid attempt')

                    return Response(
                        {'error': 'Invalid OTP. A new verification code has been sent to your email.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Issue JWT tokens
                try:
                    refresh = RefreshToken.for_user(user)
                    # For admin/manager users, ensure the audience/scope match admin endpoints
                    try:
                        if user.is_superuser or getattr(user, 'manager_admin_status', '') in ['Admin', 'Manager']:
                            refresh['aud'] = 'admin.vtindex'
                            refresh['scope'] = 'admin:*'
                            access = refresh.access_token
                            access['aud'] = 'admin.vtindex'
                            access['scope'] = 'admin:*'
                        else:
                            # ensure client audience for non-admins
                            try:
                                refresh['aud'] = refresh.get('aud') or 'client.vtindex'
                                refresh['scope'] = refresh.get('scope') or 'client:*'
                                access = refresh.access_token
                                access['aud'] = access.get('aud') or 'client.vtindex'
                                access['scope'] = access.get('scope') or 'client:*'
                            except Exception:
                                access = refresh.access_token
                    except Exception:
                        # fallback: still get access token
                        try:
                            access = refresh.access_token
                        except Exception:
                            access = None

                    # Record outstanding access so it can be revoked later (best-effort)
                    try:
                        if access is not None:
                            access.outstand()
                    except Exception:
                        logger.exception('Failed to create OutstandingToken after OTP verification')

                    access_token = str(access) if access is not None else str(refresh.access_token)

                    role_mapping = {
                        'Admin': 'admin',
                        'Manager': 'manager',
                        'Client': 'client',
                        'None': 'client'
                    }
                    frontend_role = role_mapping.get(user.manager_admin_status, 'client')

                    # Clear login OTP
                    user.login_otp = None
                    user.login_otp_created_at = None
                    user.save(update_fields=['login_otp', 'login_otp_created_at'])

                    # Log activity (non-blocking)
                    try:
                        ActivityLog.objects.create(
                            user=user,
                            activity="User login via client portal (verified new IP)",
                            ip_address=get_client_ip(request),
                            endpoint=request.path,
                            activity_type="update",
                            activity_category="client",
                            status_code=200,
                            user_agent=request.META.get("HTTP_USER_AGENT", ""),
                            timestamp=timezone.now(),
                            related_object_id=user.id,
                            related_object_type="Login"
                        )
                    except Exception:
                        logger.exception("ActivityLog creation failed")

                    resp_body = {
                        'access': access_token,
                        'refresh': str(refresh),
                        'role': frontend_role,
                        'redirect_url': compute_redirect_url(request, frontend_role),
                        'user': {
                            'email': user.email,
                            'name': (
                                f'{user.first_name} {user.last_name}'.strip()
                                or user.username
                            )
                        }
                    }

                    # Set cookies in same format as admin login (best-effort)
                    try:
                        secure_flag = not settings.DEBUG
                        try:
                            refresh_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('REFRESH_TOKEN_LIFETIME', None)
                            access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', None)
                            refresh_max_age = int(refresh_lifetime.total_seconds()) if refresh_lifetime else None
                            access_max_age = int(access_lifetime.total_seconds()) if access_lifetime else None
                        except Exception:
                            refresh_max_age = None
                            access_max_age = None

                        cookie_domain = getattr(settings, 'COOKIE_DOMAIN', None)

                        resp = Response(resp_body, status=200)
                        if access_token:
                            resp.set_cookie('jwt_token', access_token, httponly=True, secure=secure_flag,
                                            samesite='Strict', path='/', max_age=access_max_age, domain=cookie_domain)
                            resp.set_cookie('access_token', access_token, httponly=True, secure=secure_flag,
                                            samesite='Strict', path='/', max_age=access_max_age, domain=cookie_domain)
                            resp.set_cookie('accessToken', access_token, httponly=True, secure=secure_flag,
                                            samesite='Strict', path='/', max_age=access_max_age, domain=cookie_domain)

                        if resp_body.get('refresh'):
                            resp.set_cookie('refresh_token', resp_body['refresh'], httponly=True, secure=secure_flag,
                                            samesite='Strict', path='/', max_age=refresh_max_age, domain=cookie_domain)
                    except Exception:
                        logger.exception('Failed to set auth cookies after OTP verification')
                        resp = Response(resp_body, status=200)

                    # Expose role to frontend via non-HttpOnly cookie and legacy name `UserRole`
                    try:
                        resp.set_cookie('role', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/', domain=cookie_domain)
                        resp.set_cookie('UserRole', frontend_role, httponly=False, secure=secure_flag, samesite='Lax', path='/', domain=cookie_domain)
                    except Exception:
                        logger.exception('Failed to set role cookies after OTP verification')

                    return resp
                except Exception:
                    logger.exception("JWT issuance failed after OTP verification")
                    return Response(
                        {'message': 'OTP verified, but session creation failed. Please login again.'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

            # ============================================================
            # PASSWORD RESET OTP FLOW
            # ============================================================
            if not user.otp:
                return Response(
                    {'error': 'No OTP found. Please request a new one.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if (
                user.otp_created_at and
                timezone.now() - user.otp_created_at > timedelta(minutes=10)
            ):
                user.otp = None
                user.otp_created_at = None
                user.save(update_fields=['otp', 'otp_created_at'])

                return Response(
                    {'error': 'OTP has expired. Please request a new one.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user.otp != otp:
                # Verify OTP against stored hash for password-reset
                from adminPanel.views.auth_views import verify_otp as verify_otp_hash
                if not verify_otp_hash(user.otp, otp):
                    # Generate and send a new password-reset OTP on invalid attempt
                    try:
                        new_otp = f"{random.randint(100000, 999999)}"
                        # Hash the new OTP before storing
                        hashed_otp = hash_otp(new_otp)
                        user.otp = hashed_otp
                        user.otp_created_at = timezone.now()
                        user.save(update_fields=['otp', 'otp_created_at'])
                        try:
                            EmailSender.send_otp_email(user.email, new_otp)
                        except Exception:
                            logger.exception('Failed to send regenerated password-reset OTP email')
                        try:
                            ActivityLog.objects.create(
                                user=user,
                                activity="Password-reset OTP regenerated after invalid attempt",
                                ip_address=get_client_ip(request),
                                endpoint=request.path,
                                activity_type="update",
                                activity_category="client",
                                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                                timestamp=timezone.now(),
                                related_object_id=user.id,
                                related_object_type="PasswordReset"
                            )
                        except Exception:
                            logger.exception('Failed to create ActivityLog for regenerated password-reset OTP')
                    except Exception:
                        logger.exception('Failed to regenerate password-reset OTP on invalid attempt')

                    return Response(
                        {'error': 'Invalid OTP. A new verification code has been sent to your email.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            return Response({'message': 'OTP verified successfully.'})

        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'No account found with this email'},
                status=status.HTTP_404_NOT_FOUND
            )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@csrf_exempt
def validate_token_view(request):
    """Validate JWT token from HttpOnly cookies and return user info"""
    try:
        user = request.user
        if not user.is_authenticated:
            return Response({'valid': False, 'error': 'Not authenticated'}, status=401)
        
        return Response({
            'valid': True,
            'message': 'Token is valid',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name() or user.username or user.email.split('@')[0],
                'role': getattr(user, 'manager_admin_status', 'Client'),
                'is_superuser': user.is_superuser
            }
        }, status=200)
        
    except Exception as e:
        return Response({'error': f'Validation error: {str(e)}'}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@csrf_exempt
def validate_token_view(request):
    """Validate JWT token from HttpOnly cookies and return user info"""
    try:
        user = request.user
        if not user.is_authenticated:
            return Response({'valid': False, 'error': 'Not authenticated'}, status=401)
        
        return Response({
            'valid': True,
            'message': 'Token is valid',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name() or user.username or user.email.split('@')[0],
                'role': getattr(user, 'manager_admin_status', 'Client'),
                'is_superuser': user.is_superuser
            }
        }, status=200)
        
    except Exception as e:
        return Response({'error': f'Validation error: {str(e)}'}, status=500)

@api_view(['GET'])
@permission_classes([AllowAny])
@csrf_exempt
def status_view(request):
    """Simple status endpoint that returns authentication status"""
    try:
        user = request.user
        if user.is_authenticated:
            return Response({
                'status': 'authenticated',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.get_full_name() or user.username or user.email.split('@')[0],
                }
            }, status=200)
        else:
            return Response({
                'status': 'unauthenticated'
            }, status=200)
    except Exception as e:
        return Response({'error': f'Status check error: {str(e)}'}, status=500)
