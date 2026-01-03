from django.contrib import admin
from .models import BankDetails, UserDocument
from adminPanel.models import CryptoDetails

@admin.register(BankDetails)
class BankDetailsAdmin(admin.ModelAdmin):
    list_display = ['user', 'bank_name', 'account_number', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'bank_name']
    readonly_fields = ['created_at', 'updated_at']
    actions = ['approve_bank_details', 'reject_bank_details']

    def approve_bank_details(self, request, queryset):
        queryset.update(status='approved')
        self.message_user(request, f"{queryset.count()} bank details approved.")
    approve_bank_details.short_description = "Approve selected bank details"

    def reject_bank_details(self, request, queryset):
        queryset.update(status='rejected')
        self.message_user(request, f"{queryset.count()} bank details rejected.")
    reject_bank_details.short_description = "Reject selected bank details"

# Unregister CryptoDetails if already registered and re-register with our custom admin
if CryptoDetails in admin.site._registry:
    admin.site.unregister(CryptoDetails)

@admin.register(CryptoDetails)
class CryptoDetailsAdmin(admin.ModelAdmin):
    list_display = ['user', 'wallet_address', 'currency', 'status', 'created_at']
    list_filter = ['status', 'currency', 'created_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'wallet_address']
    readonly_fields = ['created_at', 'updated_at']
    actions = ['approve_crypto_details', 'reject_crypto_details']

    def approve_crypto_details(self, request, queryset):
        queryset.update(status='approved')
        self.message_user(request, f"{queryset.count()} crypto details approved.")
    approve_crypto_details.short_description = "Approve selected crypto details"

    def reject_crypto_details(self, request, queryset):
        queryset.update(status='rejected')
        self.message_user(request, f"{queryset.count()} crypto details rejected.")
    reject_crypto_details.short_description = "Reject selected crypto details"

@admin.register(UserDocument)
class UserDocumentAdmin(admin.ModelAdmin):
    list_display = ['user', 'document_type', 'status', 'uploaded_at']
    list_filter = ['document_type', 'status', 'uploaded_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    readonly_fields = ['uploaded_at', 'updated_at']
    actions = ['approve_documents', 'reject_documents']

    def approve_documents(self, request, queryset):
        queryset.update(status='approved')
        self.message_user(request, f"{queryset.count()} documents approved.")
    approve_documents.short_description = "Approve selected documents"

    def reject_documents(self, request, queryset):
        queryset.update(status='rejected')
        self.message_user(request, f"{queryset.count()} documents rejected.")
    reject_documents.short_description = "Reject selected documents"
