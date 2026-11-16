"""
Phase 6 Admin Authentication & Authorization Integration Test Suite
Verifies 401 Unauthorized rejection for unauthenticated admin endpoint access,
successful JWT issuance for valid admin credentials, and public accessibility for /chat.
"""

import pytest
from app.core.config import settings

@pytest.mark.asyncio
async def test_unauthenticated_admin_stats_rejected(async_client):
    # Attempting to call protected admin stats without token
    response = await async_client.get("/api/v1/dashboard/stats")
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "Authentication required" in data["detail"]

@pytest.mark.asyncio
async def test_unauthenticated_admin_logs_rejected(async_client):
    # Attempting to call protected admin logs without token
    response = await async_client.get("/api/v1/dashboard/logs")
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data

@pytest.mark.asyncio
async def test_invalid_admin_login_fails(async_client):
    # Invalid password login attempt
    payload = {
        "email": settings.ADMIN_USERNAME,
        "password": "InvalidTestPassword!999"
    }
    response = await async_client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data

@pytest.mark.asyncio
async def test_valid_admin_login_succeeds(async_client):
    # Valid admin credentials from configuration
    payload = {
        "email": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_PASSWORD
    }
    response = await async_client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_authenticated_admin_stats_accessible(async_client):
    # Step 1: Login to acquire admin token
    login_payload = {
        "email": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_PASSWORD
    }
    login_res = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Step 2: Request protected admin stats with Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    response = await async_client.get("/api/v1/dashboard/stats", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_requests" in data
    assert "blocked_threats" in data

@pytest.mark.asyncio
async def test_normal_user_chat_accessible_without_admin_token(async_client):
    # Normal user chat gateway must remain publicly accessible without admin token
    payload = {
        "prompt": "What is the company's annual leave policy?",
        "llm_provider": "ollama"
    }
    response = await async_client.post("/api/v1/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["security_eval"]["verdict"] == "FORWARDED"
