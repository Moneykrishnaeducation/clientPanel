"""
Celery tasks for PAMM operations
"""
from celery import shared_task
from django.contrib.auth import get_user_model
from adminPanel.EmailSender import EmailSender
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


@shared_task(bind=True, max_retries=3)
def send_pamm_creation_email_task(self, user_id, pamm_data, mt5_data):
    """
    Async task to send PAMM account creation email
    """
    try:
        user = User.objects.get(id=user_id)
        
        EmailSender.send_pamm_account_created_email(
            user_email=user.email,
            user_name=user.get_full_name() or user.username,
            pamm_name=pamm_data['name'],
            account_id=mt5_data['mt5_login'],
            master_password=mt5_data['master_password'],
            investor_password=mt5_data['investor_password'],
            leverage=pamm_data['leverage'],
            profit_share=pamm_data['profit_share'],
            login_url="https://client.vtindex.com",
            company_name="VTIndex"
        )
        
        # logger.info(f"PAMM creation email sent successfully to {user.email}")
        return {"status": "success", "email": user.email}
        
    except User.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return {"status": "error", "message": "User not found"}
    except Exception as exc:
        logger.error(f"Failed to send PAMM creation email: {exc}")
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (self.request.retries + 1), exc=exc)
        return {"status": "error", "message": str(exc)}


@shared_task(bind=True, max_retries=3)
def send_investment_credentials_email_task(self, user_id, pamm_data, investment_data):
    """
    Async task to send investment credentials email
    """
    try:
        user = User.objects.get(id=user_id)
        
        EmailSender.send_pamm_investment_credentials_email(
            user_email=user.email,
            user_name=user.get_full_name() or user.username,
            pamm_name=pamm_data['name'],
            manager_name=pamm_data['manager_name'],
            investment_amount=investment_data['amount'],
            account_id=pamm_data['mt5_login'],
            investor_password=pamm_data['investor_password'],
            login_url="https://client.vtindex.com",
            company_name="VTIndex"
        )
        
        # logger.info(f"Investment credentials email sent successfully to {user.email}")
        return {"status": "success", "email": user.email}
        
    except User.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return {"status": "error", "message": "User not found"}
    except Exception as exc:
        logger.error(f"Failed to send investment credentials email: {exc}")
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (self.request.retries + 1), exc=exc)
        return {"status": "error", "message": str(exc)}
