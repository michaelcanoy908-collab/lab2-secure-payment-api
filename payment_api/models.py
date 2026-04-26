"""
models.py  –  payment_api
==========================
PaymentCard stores the card number ENCRYPTED (never in plaintext).
UserProfile links to Django's built-in User (which uses Argon2 via settings).
"""

from django.db import models
from django.contrib.auth.models import User
from secure_payment_api.encryption import encrypt, decrypt
import logging

logger = logging.getLogger("payment_api")


class PaymentCard(models.Model):
    """
    Stores a credit/debit card.

    card_number_encrypted  – AES (Fernet) encrypted card number
    card_holder            – plain name (not sensitive enough to encrypt here)
    last_four              – last 4 digits stored in plaintext for display
    created_at             – timestamp
    owner                  – FK to Django User
    """

    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="payment_cards"
    )
    card_holder = models.CharField(max_length=100)
    card_number_encrypted = models.TextField()          # Fernet token stored here
    last_four = models.CharField(max_length=4)          # e.g. "1111"
    expiry = models.CharField(max_length=7)             # e.g. "12/2027"
    created_at = models.DateTimeField(auto_now_add=True)

    # ── Helper properties ──────────────────────────────────────────────────
    @property
    def card_number(self) -> str:
        """Decrypt and return the full card number."""
        return decrypt(self.card_number_encrypted)

    @card_number.setter
    def card_number(self, plaintext: str):
        """Encrypt a card number before storing."""
        self.last_four = plaintext[-4:]
        self.card_number_encrypted = encrypt(plaintext)
        logger.info("Card number encrypted and stored for holder '%s'.", self.card_holder)

    def __str__(self):
        return f"{self.card_holder} — **** **** **** {self.last_four}"

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Payment Card"


class LoginAttempt(models.Model):
    """Audit log for every login attempt (success or failure)."""

    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True)

    def __str__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"[{status}] {self.username} from {self.ip_address} at {self.timestamp}"

    class Meta:
        ordering = ["-timestamp"]
        verbose_name = "Login Attempt"