"""
Client Panel Authentication Guard Middleware
Prevents direct access to protected pages without authentication
"""
from django.shortcuts import redirect
from django.urls import reverse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class ClientAuthGuardMiddleware:
    """
    Middleware to protect client panel pages from direct access.
    Redirects unauthenticated users to login page.
    """
    
    # Pages that require authentication
    PROTECTED_PATHS = [
        '/dashboard',
        '/dashboard/',
        '/manager/dashboard',
        '/manager/dashboard/',
        '/profile',
        '/profile/',
        '/trading',
        '/trading/',
        '/transactions',
        '/transactions/',
        '/partnership',
        '/partnership/',
        '/social_trading',
        '/social_trading/',
        '/deposit',
        '/deposit/',
        '/withdrawal',
        '/withdrawal/',
    ]
    
    # Public paths that don't require authentication
    PUBLIC_PATHS = [
        '/',
        '/login',
        '/login/',
        '/register',
        '/register/',
        '/forgot-password',
        '/forgot-password/',
        '/verify-otp',
        '/verify-otp/',
        '/reset-password',
        '/reset-password/',
    ]
    
    # Paths that should be ignored (API, static files, etc.)
    IGNORE_PREFIXES = [
        '/api/',
        '/static/',
        '/media/',
        '/admin/',
        '/logout/',
        '/validate-token/',
    ]
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()
    
    def __call__(self, request):
        # Check if this path should be ignored
        if any(request.path.startswith(prefix) for prefix in self.IGNORE_PREFIXES):
            return self.get_response(request)
        
        # Check if this is a protected path
        is_protected = any(request.path.startswith(path) or request.path == path 
                          for path in self.PROTECTED_PATHS)
        
        if is_protected:
            # Try to authenticate using JWT from cookies
            is_authenticated = self._check_jwt_auth(request)
            
            if not is_authenticated:
                # Redirect to login with next parameter
                login_url = '/?next=' + request.path
                return redirect(login_url)
        
        response = self.get_response(request)
        return response
    
    def _check_jwt_auth(self, request):
        """
        Check if user has valid JWT token in cookies
        """
        try:
            # Check for JWT token in cookies
            jwt_token = request.COOKIES.get('jwt_token') or request.COOKIES.get('access_token')
            
            if not jwt_token:
                return False
            
            # Try to validate the token
            try:
                validated_token = self.jwt_auth.get_validated_token(jwt_token)
                user = self.jwt_auth.get_user(validated_token)
                
                # Set user on request for downstream middleware/views
                request.user = user
                return user and user.is_authenticated
            except (InvalidToken, TokenError):
                return False
                
        except Exception:
            return False
