from celery import shared_task
from django.utils import timezone
from adminPanel.models import CustomUser, ActivityLog
from adminPanel.EmailSender import EmailSender
import logging

logger = logging.getLogger(__name__)

@shared_task(ignore_result=True)
def send_login_verification_tasks(user_id, otp, email, current_ip, login_time, first_name, request_path, user_agent):
    """Send login OTP email and record verification-required ActivityLog."""
    try:
        EmailSender.send_login_otp_email(
            email,
            otp,
            ip_address=current_ip,
            login_time=login_time,
            first_name=first_name
        )
    except Exception:
        logger.exception("Failed to send login OTP email to user (Celery task)")

    try:
        ActivityLog.objects.create(
            user_id=user_id,
            activity="Login attempt - verification required (new IP)",
            ip_address=current_ip,
            endpoint=request_path,
            activity_type="update",
            activity_category="client",
            user_agent=user_agent,
            timestamp=timezone.now(),
            related_object_id=user_id,
            related_object_type="LoginVerification"
        )
    except Exception:
        logger.exception("Failed to create ActivityLog for login verification requirement (Celery task)")


@shared_task(ignore_result=True)
def background_login_tasks(user_id, current_ip, request_path, user_agent):
    """Record login activity and optionally send new-IP notification."""
    try:
        user = CustomUser.objects.get(pk=user_id)
    except CustomUser.DoesNotExist:
        logger.warning(f"background_login_tasks: user {user_id} does not exist")
        return

    try:
        ActivityLog.objects.create(
            user=user,
            activity="User login via client portal",
            ip_address=current_ip,
            endpoint=request_path,
            activity_type="update",
            activity_category="client",
            user_agent=user_agent,
            timestamp=timezone.now(),
            related_object_id=user.id,
            related_object_type="Login"
        )
    except Exception:
        logger.exception("Failed to create ActivityLog for login (Celery task)")

    # Notify user about new IP if last_login_ip exists and differs
    try:
        if user.last_login_ip and current_ip and user.last_login_ip != current_ip:
            try:
                EmailSender.send_new_ip_login_email(
                    user.email,
                    f"{user.first_name} {user.last_name}".strip() or user.email,
                    current_ip,
                    timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                    user_agent
                )
            except Exception:
                logger.exception("Failed to send new-IP login email notification (Celery task)")
    except Exception:
        logger.exception("Error while checking/sending new-IP notification in Celery task")


@shared_task(ignore_result=True)
def write_session_task(session_key, session_data):
    """Write session data into the DB-backed session store (best-effort).
    session_data should be a dict of keys/values to set.
    """
    try:
        from django.contrib.sessions.backends.db import SessionStore
        store = SessionStore(session_key=session_key)
        for k, v in session_data.items():
            store[k] = v
        store.save()
    except Exception:
        logger.exception("Failed to write session data in Celery task")
