from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import pyotp
import random
import string
from datetime import timedelta

class User(AbstractUser):
    email = models.EmailField(unique=True) 

    # Pola dla weryfikacji email
    email_verification_code = models.CharField(max_length=10, blank=True, null=True)
    email_verification_code_expires = models.DateTimeField(blank=True, null=True)

    # Pola dla TOTP
    totp_secret = models.CharField(max_length=100, blank=True, null=True)
    is_totp_enabled = models.BooleanField(default=False)



    def generate_email_verification_code(self, validity_minutes=15):
        self.email_verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        self.email_verification_code_expires = timezone.now() + timedelta(minutes=validity_minutes)
        self.save(update_fields=['email_verification_code', 'email_verification_code_expires'])
        return self.email_verification_code

    def verify_email_code(self, code):
        if self.email_verification_code == code and \
           self.email_verification_code_expires and \
           timezone.now() < self.email_verification_code_expires:
            self.email_verification_code = None 
            self.email_verification_code_expires = None
            self.save(update_fields=['email_verification_code', 'email_verification_code_expires'])
            return True
        return False

    def generate_totp_secret_if_none(self):
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            self.save(update_fields=['totp_secret'])
        return self.totp_secret

    def get_totp_provisioning_uri(self, issuer_name="SystemApp"):
        secret = self.generate_totp_secret_if_none()
        return pyotp.totp.TOTP(secret).provisioning_uri(name=self.email, issuer_name=issuer_name)

    def verify_totp_code(self, code):
        if not self.totp_secret or not self.is_totp_enabled:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code, valid_window=1)