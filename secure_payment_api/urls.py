"""
urls.py  –  secure_payment_api (project-level)
"""

from django.urls import path
from payment_api import views

urlpatterns = [
    # Part A — Registration (Argon2 hashing)
    path("api/register/", views.register_view, name="register"),

    # Part C — Login (rate-limited: 5/min)
    path("api/login/", views.login_view, name="login"),

    # Part B — Payment cards (encrypted storage)
    path("api/cards/", views.cards_view, name="cards"),

    # Part E — Decrypt test endpoint
    path("api/cards/decrypt/", views.decrypt_card_view, name="decrypt_card"),
]

# Custom 429 handler for rate limiting
handler429 = "payment_api.views.ratelimit_exceeded"