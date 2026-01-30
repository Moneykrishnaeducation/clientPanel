from django.http import HttpResponse
from django.conf import settings
from django.views.static import serve
import os

def client_dashboard(request):
    """
    Serve the main dashboard page (main.html) for /dashboard route.
    """
    file_path = os.path.join(settings.BASE_DIR, 'static', 'clientPanel', 'index.html')
    try:
        with open(file_path, 'rb') as f:
            return HttpResponse(f.read(), content_type='text/html')
    except FileNotFoundError:
        return HttpResponse('Dashboard not found', status=404)


def serve_client_app(request):
    """
    Serve the client SPA (index.html) for all non-static, non-dashboard routes.
    """
    if request.path.startswith('/static/'):
        return serve(request, request.path[8:], document_root=settings.STATIC_ROOT)
    # If the request is for /dashboard, serve main.html instead
    if request.path == '/dashboard' or request.path == '/dashboard/':
        return client_dashboard(request)
    file_path = os.path.join(settings.BASE_DIR, 'static', 'clientPanel', 'index.html')
    try:
        with open(file_path, 'rb') as f:
            return HttpResponse(f.read(), content_type='text/html')
    except FileNotFoundError:
        return HttpResponse('Client app not found', status=404)


def serve_privacy_policy(request):
    """
    Serve a public privacy-policy HTML file from the client bundle so it can
    be opened in a new tab without requiring authentication.
    """
    # Path to the static client public folder (Vite/CRA style)
    file_path = os.path.join(settings.BASE_DIR, 'static', 'clientPanel', 'privacy-policy.html')
    try:
        with open(file_path, 'rb') as f:
            return HttpResponse(f.read(), content_type='text/html')
    except FileNotFoundError:
        return HttpResponse('Privacy policy not found', status=404)
