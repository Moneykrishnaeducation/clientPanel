from django.urls import path, re_path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

# View imports
from .views.client_app_view import serve_client_app, pamm_client_view
from .views import robots_txt, sitemap_xml
from .views import auth_views
from .views.trading_views import (
    OpenPositionsView,
    AccountDetailsView,
    UserTradingAccountsView,
    ToggleAlgoTradingView,
)
from .views.trading_groups_view import TradingGroupsView
from .views.views2 import ResetDemoBalanceView
from .views.views4 import (
    InternalTransferView, UserDocumentView, UserProfileView, IBReferralLinkView, IBTradingAccountsView,
    IBStatusView, IBCommissionBalanceView, IBCommissionTransactionsView, IBTransactionsView,
    StatsOverviewView, UserBankDetailsView, CheckCentAccountView
)
from .views.email_document_views import (
    EmailBasedDocumentLookupView, get_documents_by_status, bulk_document_status
)
from .views.views3 import (
    ChangeRequestView, 
    BankDetailsRequestStatusView,
    CreateMAMAccountView,
    UserMAMAccountsView,
    MamProfitDetailsView,
    ToggleMamAlgoView,
    ToggleMamTradingStatusView,
    MamInvestorsView,
    AvailableMAMManagersView,
    CreateMAMInvestmentAccountView
)
from .views.views2 import IBRequestView, TicketsView, TicketMessagesView, SendMessageView, ChangeTicketStatusView  # Add ticket views import
from .views.views2 import IBRequestView, TicketsView, TicketMessagesView, SendMessageView, ChangeTicketStatusView, AdminTicketsView
from .views.views import (
    WithdrawRequestView,
    WithdrawInfoView,
    USDINRRateView,  # Add USDINRRateView import
    CheesePayInitiateView,
    CheesePayNotifyView,
    ManualDepositView,
    USDTDepositView,
    BankDetailsView,
    CryptoDetailsView,
    ClientUpdateLeverageView,
    ClientUpdatePasswordView,
    BankDetailsRequestView,  # Add this import
    CryptoDetailsRequestView,  # Add this import
    user_info_view  # Add user_info_view import
)
from .views import pamm_views
from django.urls import path, include, re_path
# Import notification views from adminPanel
from adminPanel.views.notification_views import (
    get_notifications,
    mark_notification_read,
    mark_all_notifications_read,
    delete_notification,
    get_unread_count,
    create_notification
)

# Define API patterns
api_patterns = [
    # System endpoints
    path('health-check/', lambda request: JsonResponse({'status': 'ok'}), name='api-health-check'),
    path('status/', csrf_exempt(auth_views.status_view), name='api-status'),
    
    # Auth endpoints
    path('signup/', csrf_exempt(auth_views.signup_view), name='api-signup'),
    path('login/', csrf_exempt(auth_views.client_login_view), name='api-login'),
    path('reset-password/', csrf_exempt(auth_views.reset_password_view), name='api-reset-password'),
    path('send-reset-otp/', csrf_exempt(auth_views.send_reset_otp_view), name='api-send-reset-otp'),
    path('send-signup-otp/', csrf_exempt(auth_views.send_signup_otp_view), name='api-send-signup-otp'),
    path('verify-otp/', csrf_exempt(auth_views.VerifyOtpView.as_view()), name='api-verify-otp'),
    path('verify-signup-otp/', csrf_exempt(auth_views.verify_signup_otp_view), name='api-verify-signup-otp'),
    path('resend-login-otp/', csrf_exempt(auth_views.resend_login_otp_view), name='api-resend-login-otp'),
    path('login-otp-status/', csrf_exempt(auth_views.login_otp_status_view), name='api-login-otp-status'),
    path('validate-token/', csrf_exempt(auth_views.validate_token_view), name='api-validate-token'),
    path('resend-otp/', csrf_exempt(auth_views.resend_login_otp_view), name='api-resend-otp'),
    
    # Document management endpoints
    path('profile/documents/<str:doc_type>/', csrf_exempt(UserDocumentView.as_view()), name='api-upload-document'),
    path('profile/documents/', csrf_exempt(UserDocumentView.as_view()), name='api-get-documents'),
    
    # Email-based document lookup endpoints (optimized for faster retrieval)
    path('documents/by-email/<str:email>/', csrf_exempt(EmailBasedDocumentLookupView.as_view()), name='api-documents-by-email'),
    path('documents/by-email/<str:email>/<str:document_type>/', csrf_exempt(EmailBasedDocumentLookupView.as_view()), name='api-documents-by-email-type'),
    path('documents/by-email/<str:email>/status/<str:doc_status>/', csrf_exempt(get_documents_by_status), name='api-documents-by-email-status'),
    path('documents/bulk-status/', csrf_exempt(bulk_document_status), name='api-bulk-document-status'),
    
    # Exchange rate endpoint
    path('usd-inr-rate/', csrf_exempt(USDINRRateView.as_view()), name='api-usd-inr-rate'),
    
    # Account management endpoints
    path('account-details/<str:account_id>/', csrf_exempt(AccountDetailsView.as_view()), name='api-account-details'),
    path('profile/', csrf_exempt(UserProfileView.as_view()), name='api-profile'),
    path('user-info/', csrf_exempt(user_info_view), name='api-user-info'),
    path('profile/bank-details/', csrf_exempt(UserBankDetailsView.as_view()), name='api-bank-details'),
    path('profile/crypto-details/', csrf_exempt(CryptoDetailsView.as_view()), name='api-crypto-details'),
    
    # Request submission endpoints - these create admin pending requests
    path('requests/bank-details/', csrf_exempt(BankDetailsRequestView.as_view()), name='api-bank-details-request'),
    path('requests/crypto-details/', csrf_exempt(CryptoDetailsRequestView.as_view()), name='api-crypto-details-request'),
    path('requests/profile-change/', csrf_exempt(ChangeRequestView.as_view()), name='api-profile-change-request'),
    path('requests/bank-details/status/', csrf_exempt(BankDetailsRequestStatusView.as_view()), name='api-bank-details-request-status'),
    # IB endpoints
    path('ib/referral-link/', IBReferralLinkView.as_view(), name='ib-referral-link'),
    path('ib/accounts/', IBTradingAccountsView.as_view(), name='ib-accounts'),
    path('ib/status/', IBStatusView.as_view(), name='ib-status'),
    path('ib/stats/', StatsOverviewView.as_view(), name='ib-stats'),
    path('ib/commission-balance/', IBCommissionBalanceView.as_view(), name='ib-commission-balance'),
    path('ib/commission-transactions/', IBCommissionTransactionsView.as_view(), name='ib-commission-transactions'),
    path('ib/transactions/', IBTransactionsView.as_view(), name='ib-transactions'),
    path('ib-request/', csrf_exempt(IBRequestView.as_view()), name='api-ib-request'),  # Add the missing ib-request endpoint
    
    # Account type checking
    path('check-cent-account/<str:account_id>/', CheckCentAccountView.as_view(), name='api-check-cent-account'),
    
    path('internal-transfer/', InternalTransferView.as_view(), name='api-internal-transfer'),
    path('open-positions/<str:account_id>/', OpenPositionsView.as_view(), name='api-open-positions'),
    path('update-leverage/<str:account_id>/', ClientUpdateLeverageView.as_view(), name='api-update-leverage'),
    path('get-trading-positions/<str:account_id>/', OpenPositionsView.as_view(), name='api-get-trading-positions'),
    path('update-password/<str:account_id>/', ClientUpdatePasswordView.as_view(), name='api-update-password'),
     
    # Transaction endpoints
    path('withdraw-request/', WithdrawRequestView.as_view(), name='api-withdraw-request'),
    path('withdraw-info/<str:account_id>/', WithdrawInfoView.as_view(), name='api-withdraw-info'),
    path('cheesepay-initiate/', CheesePayInitiateView.as_view(), name='api-cheesepay-initiate'),
    path('manual-deposit/', ManualDepositView.as_view(), name='api-manual-deposit'),
    path('usdt-deposit/', USDTDepositView.as_view(), name='api-usdt-deposit'),
    
    # Trading endpoints
    path('trading-groups/', TradingGroupsView.as_view(), name='api-trading-groups'),
    path('user-trading-accounts/', UserTradingAccountsView.as_view(), name='api-user-trading-accounts'),  # Updated endpoint
    path('trading-accounts/', UserTradingAccountsView.as_view(), name='api-trading-accounts'),  # Keep old endpoint for backward compatibility
    path('reset-demo-balance/<str:account_id>/', ResetDemoBalanceView.as_view(), name='api-reset-demo-balance'),
    path('toggle-algo/<str:account_id>/', ToggleAlgoTradingView.as_view(), name='api-toggle-algo'),
    
    # MAM (Social Trading) endpoints
    path('mam-accounts/create/', CreateMAMAccountView.as_view(), name='api-create-mam-account'),
    path('user-mam-accounts/', UserMAMAccountsView.as_view(), name='api-user-mam-accounts'),
    path('mam-profit-details/<str:mam_id>/', MamProfitDetailsView.as_view(), name='api-mam-profit-details'),
    path('toggle-mam-algo/<str:mam_id>/', ToggleMamAlgoView.as_view(), name='api-toggle-mam-algo'),
    path('toggle-mam-status/<str:mam_id>/', ToggleMamTradingStatusView.as_view(), name='api-toggle-mam-status'),
    path('mam/investments/', CreateMAMInvestmentAccountView.as_view(), name='api-create-mam-investment'),
    path('mam-investors/<str:mam_id>/', MamInvestorsView.as_view(), name='api-mam-investors'),
    path('available-mam-managers/', AvailableMAMManagersView.as_view(), name='api-available-mam-managers'),
    path('start-copying/', csrf_exempt(lambda req: JsonResponse({'status': 'success'})), name='api-start-copying'),
    path('pause-copying/', csrf_exempt(lambda req: JsonResponse({'status': 'success'})), name='api-pause-copying'),

     # Ticket endpoints
    path('tickets/', TicketsView.as_view(), name='api-tickets'),
    path('admin-tickets/', AdminTicketsView.as_view(), name='api-admin-tickets'),
    path('tickets/<int:ticket_id>/messages/', TicketMessagesView.as_view(), name='api-ticket-messages'),
    path('tickets/<int:ticket_id>/send-message/', SendMessageView.as_view(), name='api-ticket-send-message'),
    path('tickets/<int:ticket_id>/change-status/', ChangeTicketStatusView.as_view(), name='api-ticket-change-status'),

    # Notification endpoints
    path('notifications/', get_notifications, name='api-client-notifications'),
    path('notifications/<int:notification_id>/mark-read/', mark_notification_read, name='api-mark-notification-read'),
    path('notifications/mark-all-read/', mark_all_notifications_read, name='api-mark-all-notifications-read'),
    path('notifications/<int:notification_id>/delete/', delete_notification, name='api-delete-notification'),
    path('notifications/unread-count/', get_unread_count, name='api-notification-unread-count'),
    path('notifications/create/', create_notification, name='api-create-notification'),


    # PAMM endpoints
    path('pamm/managed/', pamm_views.managed_pamm_list, name='api-pamm-managed'),
    path('pamm/create/', pamm_views.create_pamm_account, name='api-pamm-create'),
    path('pamm/available/', pamm_views.available_pamm_list, name='api-pamm-available'),
    path('pamm/investments/', pamm_views.user_investments, name='api-pamm-investments'),
    path('pamm/invest/', pamm_views.invest_in_pamm, name='api-pamm-invest'),
    path('pamm/disable/', pamm_views.disable_pamm_account, name='api-pamm-disable'),
    path('pamm/leave/', pamm_views.leave_pamm_investment, name='api-pamm-leave'),
    path('pamm/deposit/', pamm_views.deposit_to_pamm, name='api-pamm-deposit'),
    path('pamm/withdraw/', pamm_views.withdraw_from_pamm, name='api-pamm-withdraw'),
]

# Main URL patterns
urlpatterns = [
    # Quick aliases: expose a few compatibility endpoints at the site root
    # (Some frontends call these without the /api/ prefix or with /client/api/)
    path('resend-login-otp/', csrf_exempt(auth_views.resend_login_otp_view), name='api-resend-login-otp'),
    # Keep the original API mounts for compatibility
    path('api/', include(api_patterns)),
    path('client/api/', include(api_patterns)),  # Add client prefix for frontend compatibility
    # Direct notification endpoints (for /client/notifications/ paths)
    path('client/notifications/', get_notifications, name='client-notifications'),
    path('client/notifications/<int:notification_id>/mark-read/', mark_notification_read, name='client-mark-notification-read'),
    path('client/notifications/mark-all-read/', mark_all_notifications_read, name='client-mark-all-notifications-read'),
    path('client/notifications/<int:notification_id>/delete/', delete_notification, name='client-delete-notification'),
    path('client/notifications/unread-count/', get_unread_count, name='client-notification-unread-count'),
    path('client/notifications/create/', create_notification, name='client-create-notification'),


    # Static files
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),

    # Client app specific routes
    # CheezePay webhook notification endpoint (platform posts here)
    path('client/cheezepay-notify/', CheesePayNotifyView.as_view(), name='client-cheezepay-notify'),

    path('client/login/', serve_client_app, name='client-login'),
    path('client/dashboard/', serve_client_app, name='client-dashboard'),
    path('login/', serve_client_app, name='login'),
    path('dashboard/', serve_client_app, name='dashboard'),
    # PAMM client page (serves the PAMM-specific client UI and enforces auth/jwt handling)
    path('pamm/', pamm_client_view, name='pamm-client'),

    # Legacy direct endpoints (some frontend code hits these paths without /api/)
    path('manual-deposit/', ManualDepositView.as_view(), name='legacy-manual-deposit'),
    path('usdt-deposit/', USDTDepositView.as_view(), name='legacy-usdt-deposit'),
    path('cheesepay-initiate/', CheesePayInitiateView.as_view(), name='legacy-cheesepay-initiate'),
    # Expose toggle-algo at site root for older frontends that call `/toggle-algo/...`
    path('toggle-algo/<str:account_id>/', ToggleAlgoTradingView.as_view(), name='legacy-toggle-algo'),
    # Expose toggle-algo at site root for older frontends that call `/toggle-algo/...`
    path('mam/investments/', CreateMAMInvestmentAccountView.as_view(), name='legacy-mam-investments'),
    # Serve client app - catch-all route must be last
    re_path(r'^.*$', serve_client_app, name='client-app'),
]

# Add static/media file serving in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
