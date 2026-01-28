from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from adminPanel.models import TradeGroup
import logging

logger = logging.getLogger(__name__)

class TradingGroupsView(APIView):
    """
    API endpoint to return only enabled/active trading groups for client panel.
    Used by the frontend to populate the trading group dropdown in account creation.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Return list of enabled trading groups that can be used for account creation.
        Only returns groups where is_active=True (admin-selected groups).
        Filters by account type to only show appropriate groups.
        """
        try:
            # Get account type from query parameter (default to 'real')
            account_type = request.GET.get('type', 'real').lower()
            
            # Get only active/enabled groups for the specified account type
            if account_type == 'demo':
                active_groups = TradeGroup.objects.filter(
                    is_active=True, 
                    type='demo'
                ).order_by('name')
            else:
                # For real accounts, only show real/live groups
                active_groups = TradeGroup.objects.filter(
                    is_active=True, 
                    type='real'
                ).order_by('name')
            
            # Debug: Log what we actually got

            # For demo account type we should return all active demo groups
            # regardless of whether they have an alias. For real accounts keep
            # the server-side alias requirement to maintain existing client
            # expectations for live groups.
            if account_type == 'demo':
                filtered_groups = active_groups
            else:
                # Server-side: only include real groups that have an explicit, non-empty alias
                filtered_groups = active_groups.filter(alias__isnull=False).exclude(alias__exact='')

            # Additionally, exclude any group whose alias contains 'cent' in any casing
            # (covers 'cent', 'Cent', 'cENT', etc.). This applies to both demo and real results.
            filtered_groups = filtered_groups.exclude(alias__icontains='cent')

            groups_data = []
            for group in filtered_groups:
                groups_data.append({
                    'id': group.id,
                    'name': group.name,
                    # Do NOT fall back to name here; only return explicit alias
                    'alias': group.alias,
                    'description': group.description or '',
                    'type': group.type,
                    'is_default': group.is_default if group.type == 'real' else False,
                    'is_demo_default': group.is_demo_default if group.type == 'demo' else False
                })
            
            return Response({
                'success': True,
                'groups': groups_data,
                'total': len(groups_data),
                'account_type': account_type
            })
            
        except Exception as e:
            logger.error(f"Error fetching trading groups: {str(e)}", exc_info=True)
            return Response({
                'success': False,
                'error': str(e),
                'groups': [],
                'account_type': account_type if 'account_type' in locals() else 'real'
            }, status=500)