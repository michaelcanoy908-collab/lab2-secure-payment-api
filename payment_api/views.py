"""
views.py  –  payment_api
=========================
Endpoints:
  POST /api/register/       – create user (Argon2 hashed password)
  POST /api/login/          – authenticate  [rate-limited: 5/min per IP]
  POST /api/cards/          – add a payment card (encrypted)  [auth required]
  GET  /api/cards/          – list cards (masked)             [auth required]
  POST /api/cards/decrypt/  – decrypt a specific card         [auth required]
"""

import json
import logging

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

# Part C: Rate limiting
from django_ratelimit.decorators import ratelimit

from .models import LoginAttempt, PaymentCard
from secure_payment_api.encryption import decrypt

logger = logging.getLogger("payment_api")
security_logger = logging.getLogger("security")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_client_ip(request) -> str:
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def _json_body(request) -> dict:
    try:
        return json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return {}


def _require_auth(request):
    """Return the authenticated User or None."""
    if not request.user.is_authenticated:
        return None
    return request.user


# ── Part A: Registration — Argon2 password hashing ───────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
def register_view(request):
    """
    POST /api/register/
    Body: { "username": "...", "password": "...", "email": "..." }

    Django's create_user() automatically hashes the password using the
    first hasher in PASSWORD_HASHERS — which we set to Argon2.
    """
    data = _json_body(request)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    email = data.get("email", "").strip()

    if not username or not password:
        return JsonResponse({"error": "username and password are required."}, status=400)

    if User.objects.filter(username=username).exists():
        return JsonResponse({"error": "Username already taken."}, status=409)

    # create_user calls set_password() → Argon2PasswordHasher
    user = User.objects.create_user(username=username, password=password, email=email)
    logger.info("New user registered: '%s'.", username)

    return JsonResponse(
        {
            "message": "User registered successfully.",
            "user_id": user.pk,
            "password_hash_algorithm": "argon2",  # confirm hashing used
        },
        status=201,
    )


# ── Part C: Login — rate limited ─────────────────────────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
@ratelimit(key="ip", rate="5/m", block=True)   # ← 5 requests per minute per IP
def login_view(request):
    """
    POST /api/login/
    Body: { "username": "...", "password": "..." }

    Rate-limited to 5 attempts/minute per IP.
    All attempts (success & failure) are logged to LoginAttempt table + security log.
    """
    ip = _get_client_ip(request)
    data = _json_body(request)
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = authenticate(request, username=username, password=password)

    # Audit every attempt
    LoginAttempt.objects.create(
        username=username,
        ip_address=ip,
        success=user is not None,
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
    )

    if user is None:
        security_logger.warning(
            "FAILED login attempt | username='%s' | ip=%s", username, ip
        )
        return JsonResponse({"error": "Invalid credentials."}, status=401)

    # Successful login — log to general log
    logger.info("Successful login | username='%s' | ip=%s", username, ip)

    # In a real app you'd issue a JWT or session token here
    return JsonResponse(
        {"message": "Login successful.", "username": user.username, "user_id": user.pk},
        status=200,
    )


# ── Part B: Payment Cards — encrypted storage ─────────────────────────────────

@csrf_exempt
@require_http_methods(["POST", "GET"])
def cards_view(request):
    """
    POST /api/cards/  – store a new encrypted card
    GET  /api/cards/  – list cards (masked, no plaintext numbers)
    """
    user = _require_auth(request)
    if user is None:
        security_logger.warning("Unauthenticated access attempt to /api/cards/ from ip=%s", _get_client_ip(request))
        return JsonResponse({"error": "Authentication required."}, status=401)

    # ── POST: create card ───────────────────────────────────────────────────
    if request.method == "POST":
        data = _json_body(request)
        card_number = data.get("card_number", "").replace(" ", "").replace("-", "")
        card_holder = data.get("card_holder", "").strip()
        expiry = data.get("expiry", "").strip()

        if not card_number or not card_holder or not expiry:
            return JsonResponse(
                {"error": "card_number, card_holder, and expiry are required."}, status=400
            )

        if len(card_number) < 13 or not card_number.isdigit():
            return JsonResponse({"error": "Invalid card number format."}, status=400)

        card = PaymentCard(owner=user, card_holder=card_holder, expiry=expiry)
        card.card_number = card_number   # triggers the setter → encrypts
        card.save()

        logger.info(
            "Payment card added | owner='%s' | last_four='%s'", user.username, card.last_four
        )

        return JsonResponse(
            {
                "message": "Card stored securely (encrypted).",
                "card_id": card.pk,
                "last_four": card.last_four,
                "stored_as": card.card_number_encrypted[:40] + "…",  # snippet of token
            },
            status=201,
        )

    # ── GET: list cards (masked) ────────────────────────────────────────────
    cards = PaymentCard.objects.filter(owner=user)
    return JsonResponse(
        {
            "cards": [
                {
                    "id": c.pk,
                    "card_holder": c.card_holder,
                    "masked_number": f"**** **** **** {c.last_four}",
                    "expiry": c.expiry,
                    "created_at": c.created_at.isoformat(),
                }
                for c in cards
            ]
        },
        status=200,
    )


# ── Part E: Decrypt endpoint (tests invalid payload handling) ─────────────────

@csrf_exempt
@require_http_methods(["POST"])
def decrypt_card_view(request):
    """
    POST /api/cards/decrypt/
    Body: { "token": "<fernet-token>" }

    Used in security testing to verify invalid/tampered payloads are rejected.
    """
    user = _require_auth(request)
    if user is None:
        security_logger.warning(
            "Unauthenticated decrypt attempt from ip=%s", _get_client_ip(request)
        )
        return JsonResponse({"error": "Authentication required."}, status=401)

    data = _json_body(request)
    token = data.get("token", "")

    if not token:
        return JsonResponse({"error": "token is required."}, status=400)

    try:
        plaintext = decrypt(token)
        return JsonResponse({"decrypted": plaintext}, status=200)
    except ValueError as exc:
        security_logger.warning(
            "INVALID encrypted payload submitted by user='%s' | ip=%s | error=%s",
            user.username,
            _get_client_ip(request),
            str(exc),
        )
        return JsonResponse({"error": "Invalid or tampered encrypted payload."}, status=400)


# ── Rate-limit exceeded handler ───────────────────────────────────────────────

def ratelimit_exceeded(request, exception):
    """Custom 429 handler for django-ratelimit."""
    ip = _get_client_ip(request)
    security_logger.warning("RATE LIMIT EXCEEDED | ip=%s | path=%s", ip, request.path)
    return JsonResponse(
        {"error": "Too many requests. Please wait 1 minute and try again."},
        status=429,
    )