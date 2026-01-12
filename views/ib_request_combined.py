from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import os
from django.conf import settings
from .views2 import IBRequestView

@method_decorator(csrf_exempt, name='dispatch')
class IBRequestCombinedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Serve ib-request.html for GET requests
        file_path = os.path.join(settings.BASE_DIR, 'static', 'client', 'pages', 'ib-request.html')
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

    def post(self, request, *args, **kwargs):
        # Delegate to IBRequestView's post method
        return IBRequestView.as_view({'post': 'post'})(request, *args, **kwargs)
