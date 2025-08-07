import os

from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


def send_forgot_password_mail(user,password):
    try:
        subject = "Forgot Password | Expense Tracker"
        message = f"Hello {user.first_name} {user.last_name},\n\n"
        message += "You have requested to reset your password for Expense Tracker.\n\n"
        message += f"Please use the following password to proceed with the login:\n\n"
        message += f"Password: {password}\n\n"
        message += "Thank you,\nThe Expense Tracker Team"
        send_mail(subject, message, os.environ.get("EMAIL_HOST_USER"), [user.email])
        return True

    except Exception:
        return False

def send_forgot_password_email_link(request, user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    reset_url = request.build_absolute_uri(
        reverse('reset-password', kwargs={'uid': uid, 'token': token})
    )
    subject = "Forgot Password | Expense Tracker"
    message = f'Hi {user.first_name} {user.last_name},\n\nClick the link below to reset your password:\n{reset_url}\n\nIf you didn’t request this, please ignore this email.'

    try:
        send_mail(subject, message, os.environ.get("EMAIL_HOST_USER"), [user.email])
        return True
    except Exception:
        return False