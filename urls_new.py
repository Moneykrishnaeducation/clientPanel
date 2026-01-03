from .views.views3 import EditPersonalInfoView
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.views.decorators.csrf import csrf_exempt
from .views.index import serve_client_app
from .views.client_app_view import pamm_client_view
from .views import auth_views
from .views import pamm_views
# Use wildcard imports but handle import errors gracefully
try:
    from .views.views import *
except ImportError as e:
    print(f"Warning: Some views could not be imported from views: {e}")
    # Import essential views individually as fallback
    from .views.views import (
        WithdrawRequestView,
        WithdrawInfoView,
        USDINRRateView,
        CheesePayInitiateView,
        ManualDepositView,
        USDTDepositView,
        BankDetailsView,
        CryptoDetailsView,
        ClientUpdateLeverageView,
        ClientUpdatePasswordView,
        BankDetailsRequestView,
        CryptoDetailsRequestView,
        user_info_view,
        CheesePayNotifyView,
        LogoutView,
        ValidateTokenView,
        RecentTransactionsView,
        UserAccountsView,
        UserDemoAccountsView,
        UserTransactionHistoryView,
        PendingTransactionsView,
        AvailablePackagesView,
        IBClientTreeView,
        AuthTestView,
        IBAddClientView
    )

try:
    from .views.views2 import *
except ImportError as e:
    print(f"Warning: Some views could not be imported from views2: {e}")
    from .views.views2 import (
        IBRequestView,
        TicketsView,
        TicketMessagesView,
        SendMessageView,
        ChangeTicketStatusView
    )

try:
    from .views.views3 import *
except ImportError as e:
    print(f"Warning: Some views could not be imported from views3: {e}")
    from .views.views3 import (
        ChangeRequestView,
        BankDetailsRequestStatusView
    )
from .views.views4 import (
    UserProfileImageView, UserDocumentView, UserProfileView, UserProfileBannerView, UserBankDetailsView, 
    UserCryptoDetailsView, CreateUserView, InternalTransferView,
    ToggleInvestorCopyView, IBStatusView, IBCommissionBalanceView, 
    IBCommissionTransactionsView, IBTransactionsView, IBReferralLinkView
)
# Import StatsOverviewView with alias to avoid conflicts
from .views.views4 import StatsOverviewView as IBStatsOverviewView, BasicUserInfoView
from .views.admin_approval_views import (
    PendingRequestsView, ApprovalActionView, UserVerificationStatusView
)

from .views.trading_views import (
    AccountDetailsView,
    ToggleAlgoTradingView,
    UserTradingAccountsView,
    OpenPositionsView

)
from .views.trading_groups_view import TradingGroupsView
# Import enhanced withdrawal views
from .views.withdrawal_views import (
    WithdrawalInfoView,
    WithdrawalRequestView,
    UserPaymentDetailsView,
    WithdrawalHistoryView
)
from .views.views import ClientUpdateLeverageView, ClientUpdatePasswordView
# Import USDINRRateView explicitly since wildcard import seems to have issues
# Import the new copy coefficient view
from .views.copy_coefficient_views import save_coefficient, debug_account_coefficient, get_account_coefficient
try:
    from .views.views import USDINRRateView
except ImportError:
    # Fallback: create a placeholder view if import fails
    from rest_framework.views import APIViewa
    from rest_framework.response import Response
    from rest_framework import status
from .views.auth_views import confirm_reset_password_view, send_reset_otp_view, VerifyOtpView

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
    path('signup/', csrf_exempt(auth_views.signup_view), name='api-signup'),
    path('login/', csrf_exempt(auth_views.client_login_view), name='api-login'),
    path('resend-login-otp/', csrf_exempt(auth_views.resend_login_otp_view), name='api-resend-login-otp'),
    path('login-otp-status/', csrf_exempt(auth_views.login_otp_status_view), name='api-login-otp-status'),
    path('reset-password/', csrf_exempt(auth_views.reset_password_view), name='api-reset-password'),
    path('reset-password/confirm/', csrf_exempt(confirm_reset_password_view), name='api-reset-password-confirm'),
    path('profile/edit/', csrf_exempt(EditPersonalInfoView.as_view()), name='api-edit-personal-info'),
    path('resend-otp/', csrf_exempt(auth_views.resend_login_otp_view), name='api-resend-otp'),
    path('status/', csrf_exempt(auth_views.status_view), name='api-status'),
    
    # Authentication endpoints
    path('logout/', LogoutView.as_view(), name='api-logout'),
    
    # Profile related endpoints - keep profile/image before profile/
    path('profile/image/', csrf_exempt(UserProfileImageView.as_view()), name='api-profile-image'),

    path('profile/banner/', UserProfileBannerView.as_view(), name='api-profile-banner'),    

    # Exchange rate endpoint
    path('get-usd-inr-rate/', USDINRRateView.as_view(), name='usd-inr-rate'),

    path('profile/documents/<str:doc_type>/', UserDocumentView.as_view(), name='api-upload-document'),
    path('profile/documents/', UserDocumentView.as_view(), name='api-get-documents'),
    path('profile/', UserProfileView.as_view(), name='api-profile'),

    # Core API endpoints for subdomain access
    path('user-info/', user_info_view, name='api-user-info'),
    path('basic-info/', BasicUserInfoView.as_view(), name='api-basic-info'),  # Fast basic info endpoint
    path('recent-transactions/', RecentTransactionsView.as_view(), name='api-recent-transactions'),
    path('stats-overview/', IBStatsOverviewView.as_view(), name='api-stats-overview'),  # Note: with trailing slash
    path('validate-token/', ValidateTokenView.as_view(), name='api-validate-token'),
    path('user-accounts/', UserAccountsView.as_view(), name='api-user-accounts'),
    path('user-demo-accounts/', UserDemoAccountsView.as_view(), name='api-user-demo-accounts'),
    # path('getmydetails/', GetMyDetailsView.as_view(), name='api-get-my-details'),  # TODO: Create or find this view
    path('user-transactions/', UserTransactionHistoryView.as_view(), name='api-user-transactions'),
    path('pending-transactions/', PendingTransactionsView.as_view(), name='api-pending-transactions'),
    path('user-trading-accounts/', UserTradingAccountsView.as_view(), name='api-user-trading-accounts'),
    path('trading-groups/', TradingGroupsView.as_view(), name='api-trading-groups'),
    path('create-trading-account/', CreateTradingAccountView.as_view(), name='api-create-trading-account'),
    path('manual-deposit/', csrf_exempt(ManualDepositView.as_view()), name='api-manual-deposit'),  # Add manual deposit endpoint

    # Ticket endpoints
    path('tickets/', TicketsView.as_view(), name='api-tickets'),  # GET: list tickets for user, POST: create ticket
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

    # Account management endpoints
    path('account-details/<str:account_id>/', AccountDetailsView.as_view(), name='api-account-details'),
    path('update-leverage/<str:account_id>/', ClientUpdateLeverageView.as_view(), name='api-update-leverage'),
    path('update-password/<str:account_id>/', ClientUpdatePasswordView.as_view(), name='api-update-password'),
    path('internal-transfer/', InternalTransferView.as_view(), name='api-internal-transfer'),
    path('toggle-algo-trading/<str:account_id>/', ToggleAlgoTradingView.as_view(), name='api-toggle-algo'),

    # Trading positions endpoint
    path('get-trading-positions/<int:account_id>/', OpenPositionsView.as_view(), name='api-get-trading-positions'),
    path('open-positions/<int:account_id>/', OpenPositionsView.as_view(), name='api-open-positions'),

    # Profile related endpoints
    path('profile/', UserProfileView.as_view(), name='api-profile'),
    path('profile/documents/<str:doc_type>/', UserDocumentView.as_view(), name='api-upload-document'),
    path('profile/documents/', UserDocumentView.as_view(), name='api-get-documents'),
    path('profile/bank-details/', UserBankDetailsView.as_view(), name='api-bank-details'),
    path('profile/crypto-details/', UserCryptoDetailsView.as_view(), name='api-crypto-details'),

    # Enhanced withdrawal endpoints
    path('withdrawal/info/<str:account_id>/', WithdrawalInfoView.as_view(), name='api-withdrawal-info'),
    path('withdrawal/request/', WithdrawalRequestView.as_view(), name='api-withdrawal-request'),
    path('withdrawal/history/', WithdrawalHistoryView.as_view(), name='api-withdrawal-history'),
    path('payment-details/', UserPaymentDetailsView.as_view(), name='api-payment-details'),

    # Admin approval endpoints
    path('admin/pending-requests/', PendingRequestsView.as_view(), name='api-admin-pending-requests'),
    path('admin/approve-reject/', ApprovalActionView.as_view(), name='api-admin-approval-action'),
    path('admin/user-verification-status/<int:user_id>/', UserVerificationStatusView.as_view(), name='api-user-verification-status'),


    # CheesePay payment gateway endpoints
    path('cheesepay-initiate/', CheesePayInitiateView.as_view(), name='api-cheesepay-initiate'),
    path('cheesepay-notify/', csrf_exempt(CheesePayNotifyView.as_view()), name='api-cheesepay-notify'),
    path('cheesepay-notify', csrf_exempt(CheesePayNotifyView.as_view()), name='api-cheesepay-notify-no-slash'),
    # Accept both spellings used across code and integrations: 'cheesepay' and 'cheezepay'
    path('cheezepay-notify/', csrf_exempt(CheesePayNotifyView.as_view()), name='api-cheezepay-notify'),
    path('cheezepay-notify', csrf_exempt(CheesePayNotifyView.as_view()), name='api-cheezepay-notify-no-slash'),

    # Test endpoint for debugging
    path('auth-test/', AuthTestView.as_view(), name='api-auth-test'),

    # IB request endpoint
    path('ib-request/', IBRequestView.as_view(), name='api-ib-request'),
    path('ib/referral-link/', IBReferralLinkView.as_view(), name='ib-referral-link'),
    path('send-reset-otp/', csrf_exempt(send_reset_otp_view), name='api-send-reset-otp'),
    path('send-signup-otp/', csrf_exempt(auth_views.send_signup_otp_view), name='api-send-signup-otp'),
    path('verify-signup-otp/', csrf_exempt(auth_views.verify_signup_otp_view), name='api-verify-signup-otp'),
    path('verify-otp/', csrf_exempt(VerifyOtpView.as_view()), name='api-verify-otp'),
    path('reset-password/confirm/', csrf_exempt(confirm_reset_password_view), name='api-confirm-reset-password'),

    path("create-demo-account/", CreateDemoAccountView.as_view(), name="create_demo_account"),
    path("update-demo-account/", UpdateDemoAccountView.as_view(), name="update_demo_account"),

    # MAM coefficient saving endpoint
    path("save-coefficient/", csrf_exempt(save_coefficient), name="save_coefficient"),
    # Get current coefficient settings
    path("account-coefficient/<str:account_id>/", get_account_coefficient, name="get_account_coefficient"),
    # Debug endpoint (admin only) to inspect account copy settings
    path('debug/account-coeff/<str:account_id>/', debug_account_coefficient, name='debug-account-coeff'),

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

# Define client-specific patterns
client_patterns = [
    path('', serve_client_app, name='client-home'),
    path('dashboard/', serve_client_app, name='client-dashboard'),
    # PAMM client page
    path('pamm/', pamm_client_view, name='pamm-client'),
    path('register', serve_client_app, name='client-register'),
    path('register/', serve_client_app, name='client-register-slash'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path("validate-token/", ValidateTokenView.as_view(), name="validate-token"),    path('user-info/', user_info_view, name='user_info'),
    path('recent-transactions/', RecentTransactionsView.as_view(), name='recent-transactions'),
    path('user-trading-accounts/', UserTradingAccountsView.as_view(), name='user-trading-accounts'),
    path('user-accounts/', UserAccountsView.as_view(), name='user-accounts'),
    path("user-demo-accounts/", UserDemoAccountsView.as_view(), name="user-demo-accounts"),
    path("getmydetails/", GetMyDetailsView.as_view(), name="get_my_details"),
    path('user-transactions/', UserTransactionHistoryView.as_view(), name='user_transactions'),
    path('pending-transactions/', PendingTransactionsView.as_view(), name='pending_transactions'),
    path("packages/", AvailablePackagesView.as_view(), name="available-packages"),
    path('client/ib/stats/', IBStatsOverviewView.as_view(), name='ib-stats'),
    path('client/ib/status/', IBStatusView.as_view(), name='ib-status'),
    path("client/ib/client-tree/", IBClientTreeView.as_view(), name="ib-client-tree"),
    path("client/ib/add-client/", IBAddClientView.as_view(), name="ib-add-client"),
    path("client/ib/commission-transactions/", IBCommissionTransactionsView.as_view(), name="ib-commission-transactions"),
    path("client/ib/commission-balance/", IBCommissionBalanceView.as_view(), name="commission-balance"),
    path("client/ib/request-withdrawal/", RequestWithdrawalView.as_view(), name="request-withdrawal"),    
    path("client/ib/transactions/", IBTransactionsView.as_view(), name="transactions"),
    path("manual-deposit/", ManualDepositView.as_view(), name="manual_deposit"),
    path("cheesepay-initiate/", csrf_exempt(CheesePayInitiateView.as_view()), name="cheesepay_initiate"),
    path("cheesepay-notify/", CheesePayNotifyView.as_view(), name="cheesepay_initiate"),
    path("cheesepay-notify", CheesePayNotifyView.as_view(), name="cheesepay_initiate_no_slash"),
    # Also accept posts that include the '/client/' prefix (some senders use that path)
    path('client/cheezepay-notify/', CheesePayNotifyView.as_view(), name='client-cheezepay-notify'),
    path('client/cheezepay-notify', CheesePayNotifyView.as_view(), name='client-cheezepay-notify-no-slash'),
    path("usdt-deposit/", USDTDepositView.as_view(), name="usdt_deposit"),
    path("withdraw-info/<str:mam_id>/", WithdrawInfoView.as_view(), name="withdraw_info"),
    # Accept both spellings for webhook posting
    path("cheezepay-notify/", CheesePayNotifyView.as_view(), name="cheezepay_initiate"),
    path("cheezepay-notify", CheesePayNotifyView.as_view(), name="cheezepay_initiate_no_slash"),
    path("withdraw-request/", WithdrawRequestView.as_view(), name="withdraw_request"),
    
    # Enhanced withdrawal endpoints (new)
    path("withdrawal/info/<str:account_id>/", WithdrawalInfoView.as_view(), name="withdrawal-info"),
    path("withdrawal/request/", WithdrawalRequestView.as_view(), name="withdrawal-request"),
    path("withdrawal/history/", WithdrawalHistoryView.as_view(), name="withdrawal-history"),
    path("payment-details/", UserPaymentDetailsView.as_view(), name="payment-details"),

    path('user/details', UserDetailsWithDocumentsView.as_view(), name='user-details-with-documents'),
    path("bank-details/", BankDetailsView.as_view(), name="bank-details"),
    path("crypto-details/", CryptoDetailsView.as_view(), name="crypto-details"),
    path("available-mam-managers/", AvailableMAMManagersView.as_view(), name="available-mam-managers"),
    path("user-mam-accounts/", UserMAMAccountsView.as_view(), name="user-mam-accounts"),
    path('mam-accounts/create/', CreateMAMAccountView.as_view(), name='create_mam_account'),
    path('mam/<str:mam_id>/profits/', MamProfitDetailsView.as_view(), name='mam-profits-details'),
    path("toggle-mam-algo/", ToggleMamAlgoView.as_view(), name="toggle-mam-algo"),
    path("toggle-mam-account/", ToggleMamTradingStatusView.as_view(), name="toggle-mam-account"),
    path("mam/<str:mam_id>/investors/", MamInvestorsView.as_view(), name="mam-investors"),
    path('mam-requests/', CreateMAMInvestmentAccountView.as_view(), name='create-mam-request'),
    path('mam/investments/', CreateMAMInvestmentAccountView.as_view(), name='create-mam-investment'),
    path('user-investments/', UserInvestmentsView.as_view(), name='user-investments'),    path('pause-copying/', PauseCopyingView.as_view(), name='pause-copying'),
    path('start-copying/', StartCopyingView.as_view(), name='start-copying'),
    path('user/prop-accounts/', UserTradingAccountsView.as_view(), name='prop-trading-accounts'),
    path("mam/investors/<str:account_id>/toggle-copy", ToggleInvestorCopyView.as_view(), name="toggle-investor-copy"),
    path("basic-info/", BasicUserInfoView.as_view(), name="basic-info"),  # Fast basic info endpoint
    path("stats-overview", IBStatsOverviewView.as_view(), name="stats-overview"),
    path("stats-overview/", IBStatsOverviewView.as_view(), name="stats-overview-slash"),  # With trailing slash
    path('signup/', CreateUserView.as_view(), name='create-user'),
    path("internal-transfer", InternalTransferView.as_view(), name="internal-transfer"),
    path('get-usd-inr-rate/', USDINRRateView.as_view(), name='usd-inr-rate'),
    path("create-demo-account/", CreateDemoAccountView.as_view(), name="create_demo_account"),
    path("create-live-account/", CreateTradingAccountView.as_view(), name="create_live_account"),
    path("reset-demo-balance/<str:account_id>/", ResetDemoBalanceView.as_view(), name="reset_demo_balance"),
    path("change-demo-leverage/<str:account_id>/", ChangeDemoLeverageView.as_view(), name="change_demo_leverage"),
    path("tickets/create/", CreateTicketView.as_view(), name="create_ticket"),
    path("tickets/my-tickets/", UserTicketsView.as_view(), name="user_tickets"),
    path("tickets/<int:ticket_id>/messages", TicketMessagesView.as_view(), name="ticket_messages"),
    path("tickets/<int:ticket_id>/send-message/", SendMessageView.as_view(), name="send_message"),
    path("tickets/<int:ticket_id>/change-status/", ChangeTicketStatusView.as_view(), name="change_ticket_status"),
    path("prop-trading-requests/", PropTradingRequestView.as_view(), name="prop_trading_requests"),
    path("my-requests/", MyRequestsView.as_view(), name="my_requests"),
    path("cancel-request/<int:pk>/", CancelRequestView.as_view(), name="cancel_request"),
    path("create-trading-account/", CreateTradingAccountView.as_view(), name="create-trading-account"),

    path('get-trading-positions/<int:account_id>/', OpenPositionsView.as_view(), name='get-trading-positions'),
    path('open-positions/<int:account_id>/', OpenPositionsView.as_view(), name='open-positions'),
    path('transactions', TransactionHistoryView.as_view(), name='transaction-history'),
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot_password"),
    path("verify-otp/", VerifyOtpView.as_view(), name="verify_otp"),
    path("reset-password/", ResetPasswordView.as_view(), name="reset_password"),    
    path('ib-request/', IBRequestView.as_view(), name='ib-request'),
    path("user/", UserDetailView.as_view(), name="user-detail"),
    path("user/<int:user_id>/", UserDetailView.as_view(), name="user-detail-by-id"),
    path("bank-details-request-status/", BankDetailsRequestStatusView.as_view(), name="bank-details-request-status"),
    path('bank-details-request/<int:request_id>/', CancelBankDetailsRequestView.as_view(), name='cancel-bank-request'),
    path('change-request/<int:pk>/cancel/', ChangeRequestView.as_view(), name='change-request-cancel'),
    path('profile/edit/', csrf_exempt(EditPersonalInfoView.as_view()), name='api-edit-personal-info'),
    
    # Legacy endpoint
    path("referralsignup/", signup_view, name="signup"),
]

urlpatterns = [
    # Serve static files in development
    re_path(r'^static/(?P<path>.*)$', serve, {
        'document_root': settings.STATIC_ROOT,
    }),

    # API endpoints first (before catch-all routes)
    path('api/', include((api_patterns, 'api'), namespace='api')),
    path('client/api/', include((api_patterns, 'client-api'))),  # <-- Added for /client/api/ compatibility

    # Direct login endpoints for both subdomain and path-based access
    path('login/', csrf_exempt(auth_views.client_login_view), name='direct-login'),
    path('signup/', csrf_exempt(auth_views.signup_view), name='direct-signup'),
    path('reset-password/', csrf_exempt(auth_views.reset_password_view), name='direct-reset-password'),

    # Direct notification endpoints (for /client/notifications/ paths)
    path('client/notifications/', get_notifications, name='client-notifications'),
    path('client/notifications/<int:notification_id>/mark-read/', mark_notification_read, name='client-mark-notification-read'),
    path('client/notifications/mark-all-read/', mark_all_notifications_read, name='client-mark-all-notifications-read'),
    path('client/notifications/<int:notification_id>/delete/', delete_notification, name='client-delete-notification'),
    path('client/notifications/unread-count/', get_unread_count, name='client-notification-unread-count'),
    path('client/notifications/create/', create_notification, name='client-create-notification'),
  

    # Include all client patterns
    path('', include(client_patterns)),

    re_path(r'^(?!api/|client/api/|static/|media/|admin/).*$', serve_client_app, name='catch-all'),
    # Catch-all route for the SPA (excluding API routes, media files, and all API endpoints) - TEMPORARILY DISABLED
    # re_path(r'^(?!api/|media/|static/|user-info/|stats-overview|recent-transactions/|user-trading-accounts/|create-trading-account/|user-accounts/|user-demo-accounts/|validate-token/|getmydetails/|user-transactions/|pending-transactions/|packages/|ib/|manual-deposit/|cheesepay-|usdt-deposit/|withdraw-|bank-details/|crypto-details/|available-mam-managers/|user-mam-accounts/|mam-accounts/|mam/|toggle-|user-investments/|pause-copying/|start-copying/|user/|internal-transfer|get-usd-inr-rate/|create-demo-account/|create-live-account/|reset-demo-balance/|change-demo-leverage/|tickets/|prop-trading-requests/|my-requests/|cancel-request/|open-positions/|get-trading-positions/|transactions|forgot-password/|verify-otp/|reset-password/|ib-request/|bank-details-request|change-request/).*$', serve_client_app, name='catch-all'),
]

# Add static/media serving in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
