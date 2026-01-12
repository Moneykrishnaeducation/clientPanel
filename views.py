from django.views.static import serve as static_serve
import os

# Serve robots.txt and sitemap.xml from static directory
def robots_txt(request):
    static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
    return static_serve(request, path='robots.txt', document_root=static_dir)

def sitemap_xml(request):
    static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
    return static_serve(request, path='sitemap.xml', document_root=static_dir)
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from .models import AccountDetails, BankDetails
from adminPanel.models import CryptoDetails

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
        details = BankDetails.objects.filter(user=request.user, status='approved').first()
        if not details:
            return JsonResponse({
                'success': False,
                'message': 'Bank details not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'data': {
                'user_id': details.user.id,
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
