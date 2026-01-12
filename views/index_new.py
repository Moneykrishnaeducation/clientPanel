from django.http import HttpResponse
from django.conf import settings
import os

def serve_client_app(request):
    """Serve the client application's index.html for all non-API routes."""
    file_path = os.path.join(settings.BASE_DIR, 'static', 'client', 'index.html')
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            response = HttpResponse(content, content_type='text/html')
            response['X-Frame-Options'] = 'DENY'
            response['X-Content-Type-Options'] = 'nosniff'
            response['Cache-Control'] = 'no-store'
            return response
    except FileNotFoundError:
        return HttpResponse(
            "Client application not found. Please ensure the client files are built and copied to the static directory.",
            status=404
        )
