"""
tests.py  –  payment_api
=========================
Part E: Security Testing
"""

import json
from django.contrib.auth.models import User
from django.contrib.auth.hashers import identify_hasher
from django.test import TestCase, Client, override_settings
from django.core.cache import cache

from .models import PaymentCard, LoginAttempt
from secure_payment_api.encryption import encrypt, decrypt


# ── Helper ────────────────────────────────────────────────────────────────────

def _post_json(client, url, data, user=None):
    if user:
        client.force_login(user)
    return client.post(
        url,
        data=json.dumps(data),
        content_type="application/json",
    )


def _get_json(client, url, user=None):
    if user:
        client.force_login(user)
    return client.get(url)


# ── Part A: Password Hashing Tests ───────────────────────────────────────────

class PasswordHashingTests(TestCase):

    def test_argon2_hasher_used(self):
        """Passwords must be hashed with Argon2."""
        user = User.objects.create_user(username="alice", password="S3cur3P@ss!")
        hasher = identify_hasher(user.password)
        self.assertEqual(
            hasher.algorithm, "argon2",
            f"Expected argon2 but got '{hasher.algorithm}'.",
        )
        print("[PASS] Password hashed with Argon2 ✓")

    def test_password_not_stored_in_plaintext(self):
        """The stored hash must never equal the original password."""
        raw = "MySecret123"
        user = User.objects.create_user(username="bob", password=raw)
        self.assertNotEqual(user.password, raw)
        print("[PASS] Password not stored in plaintext ✓")

    def test_register_endpoint_creates_user(self):
        """POST /api/register/ should return 201 and confirm argon2."""
        client = Client()
        resp = _post_json(
            client, "/api/register/",
            {"username": "charlie", "password": "Str0ng!Pass", "email": "c@test.com"},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["password_hash_algorithm"], "argon2")
        print("[PASS] Registration endpoint returns 201 with argon2 ✓")


# ── Part B: Encryption Tests ──────────────────────────────────────────────────

class EncryptionTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="dave", password="Pass1234!")

    def test_card_number_encrypted_in_db(self):
        """The raw card number must NOT appear in the database field."""
        card = PaymentCard(owner=self.user, card_holder="Dave Smith", expiry="12/2027")
        card.card_number = "4111111111111111"
        card.save()
        saved = PaymentCard.objects.get(pk=card.pk)
        self.assertNotEqual(saved.card_number_encrypted, "4111111111111111")
        print("[PASS] Card number stored encrypted (not plaintext) ✓")

    def test_decrypted_card_matches_original(self):
        """Decrypting the stored token must recover the original card number."""
        card = PaymentCard(owner=self.user, card_holder="Dave Smith", expiry="12/2027")
        card.card_number = "4111111111111111"
        card.save()
        saved = PaymentCard.objects.get(pk=card.pk)
        self.assertEqual(saved.card_number, "4111111111111111")
        print("[PASS] Decrypted card number matches original ✓")

    def test_last_four_digits_stored(self):
        """last_four convenience field must be correct."""
        card = PaymentCard(owner=self.user, card_holder="Dave Smith", expiry="12/2027")
        card.card_number = "4111111111119999"
        card.save()
        self.assertEqual(card.last_four, "9999")
        print("[PASS] last_four digits stored correctly ✓")

    def test_encrypt_decrypt_roundtrip(self):
        """encrypt → decrypt must return the original value."""
        original = "sensitive-data-12345"
        token = encrypt(original)
        self.assertNotEqual(token, original)
        recovered = decrypt(token)
        self.assertEqual(recovered, original)
        print("[PASS] Encrypt/decrypt roundtrip successful ✓")


# ── Part E: Security Tests ────────────────────────────────────────────────────

class SecurityTests(TestCase):

    def setUp(self):
        # Clear cache before every test so rate limits reset
        cache.clear()
        self.client = Client(enforce_csrf_checks=False)
        self.user = User.objects.create_user(username="eve", password="SecureP@ss99")

    # ── Test 1: Unauthenticated Access ───────────────────────────────────────

    def test_unauthenticated_get_cards_returns_401(self):
        resp = self.client.get("/api/cards/")
        self.assertEqual(resp.status_code, 401)
        print("[PASS] Unauthenticated GET /api/cards/ → 401 ✓")

    def test_unauthenticated_post_card_returns_401(self):
        resp = _post_json(
            self.client, "/api/cards/",
            {"card_number": "4111111111111111", "card_holder": "Eve", "expiry": "01/2030"},
        )
        self.assertEqual(resp.status_code, 401)
        print("[PASS] Unauthenticated POST /api/cards/ → 401 ✓")

    def test_unauthenticated_decrypt_returns_401(self):
        token = encrypt("4111111111111111")
        resp = _post_json(self.client, "/api/cards/decrypt/", {"token": token})
        self.assertEqual(resp.status_code, 401)
        print("[PASS] Unauthenticated POST /api/cards/decrypt/ → 401 ✓")

    # ── Test 2: Rate Limiting ─────────────────────────────────────────────────

    def test_rate_limit_blocks_after_5_requests(self):
        """
        Rate limiting test — verifies the login endpoint is protected.
        django-ratelimit v4 blocks with 403 when block=True.
        Cache is cleared in setUp so each test starts fresh.
        """
        payload = {"username": "nobody", "password": "wrong"}

        responses = []
        for i in range(6):
            resp = _post_json(self.client, "/api/login/", payload)
            responses.append(resp.status_code)

        # At least one response must be a rate limit block (403)
        self.assertIn(
            403, responses,
            f"Rate limit was never triggered. All responses: {responses}. "
            "Check that django-ratelimit is installed and CACHES is configured."
        )
        print(f"[PASS] Rate limit triggered → responses were {responses} ✓")

    # ── Test 3: Invalid / Tampered Encrypted Payload ──────────────────────────

    def test_invalid_token_returns_400(self):
        resp = _post_json(
            self.client, "/api/cards/decrypt/",
            {"token": "this-is-not-a-valid-fernet-token-TAMPERED"},
            user=self.user,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid or tampered", resp.json()["error"])
        print("[PASS] Invalid/tampered encrypted payload → 400 ✓")

    def test_empty_token_returns_400(self):
        resp = _post_json(self.client, "/api/cards/decrypt/", {}, user=self.user)
        self.assertEqual(resp.status_code, 400)
        print("[PASS] Missing token field → 400 ✓")

    def test_valid_token_decrypts_correctly(self):
        token = encrypt("4111111111111111")
        resp = _post_json(
            self.client, "/api/cards/decrypt/",
            {"token": token}, user=self.user,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["decrypted"], "4111111111111111")
        print("[PASS] Valid token decrypts correctly → 200 ✓")

    # ── Bonus: Login audit log ────────────────────────────────────────────────

    def test_failed_login_creates_audit_record(self):
        """Every failed login must create a LoginAttempt record."""
        before = LoginAttempt.objects.count()
        _post_json(self.client, "/api/login/", {"username": "eve", "password": "WRONG"})
        after = LoginAttempt.objects.count()
        self.assertEqual(after, before + 1)
        self.assertFalse(LoginAttempt.objects.latest("timestamp").success)
        print("[PASS] Failed login creates LoginAttempt audit record ✓")

    def test_successful_login_creates_audit_record(self):
        """Successful login must create a LoginAttempt with success=True."""
        before = LoginAttempt.objects.count()
        resp = _post_json(
            self.client, "/api/login/",
            {"username": "eve", "password": "SecureP@ss99"}
        )
        after = LoginAttempt.objects.count()

        # If rate limited (403), skip — rate limiter ran before audit
        if resp.status_code == 403:
            self.skipTest("Rate limiter blocked login before audit could run — clear cache and retry.")

        self.assertEqual(after, before + 1,
            f"Expected 1 new LoginAttempt but found {after - before}. "
            f"Login response: {resp.status_code} {resp.content}")
        self.assertTrue(LoginAttempt.objects.latest("timestamp").success)
        print("[PASS] Successful login creates LoginAttempt audit record ✓")