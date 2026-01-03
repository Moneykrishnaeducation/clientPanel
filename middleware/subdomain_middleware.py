"""
Middleware to handle subdomain routing for the client panel
"""
from django.conf import settings

class SubdomainMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Split the host into parts
        host = request.get_host().split('.')
        
        # If we have a subdomain and it's 'client'
        if len(host) > 2 and host[0] == 'client':
            # Store the subdomain for use in views
            request.subdomain = host[0]
            
            # If this is an API request from the client subdomain
            if not request.path.startswith('/api/'):
                # Rewrite the URL to include /api/
                request.path_info = f'/api{request.path_info}'
        else:
            request.subdomain = None

        response = self.get_response(request)
        return response
