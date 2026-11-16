"""
Phase 7 Admin Console & Policy Management Integration Test Suite
Verifies backend REST policy management endpoints (GET/PUT /api/v1/policies),
GET /api/v1/dashboard/research-analytics, JWT Bearer authorization, and
end-to-end policy modification affecting user /chat gateway decisions.
"""

import pytest
from app.core.config import settings

@pytest.mark.asyncio
async def test_get_policies_unauthenticated_rejected(async_client):
    # Attempting to fetch policies without token
    response = await async_client.get("/api/v1/policies")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_get_policies_authenticated_succeeds(async_client):
    # Step 1: Login
    login_res = await async_client.post("/api/v1/auth/login", json={
        "email": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_PASSWORD
    })
    token = login_res.json()["access_token"]

    # Step 2: Fetch active policies with Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    response = await async_client.get("/api/v1/policies", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "rules" in data
    assert "policy_name" in data

@pytest.mark.asyncio
async def test_get_research_analytics_authenticated_succeeds(async_client):
    # Step 1: Login
    login_res = await async_client.post("/api/v1/auth/login", json={
        "email": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_PASSWORD
    })
    token = login_res.json()["access_token"]

    # Step 2: Fetch research analytics
    headers = {"Authorization": f"Bearer {token}"}
    response = await async_client.get("/api/v1/dashboard/research-analytics", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "models" in data
    assert len(data["models"]) >= 4
    assert data["held_out_test_set_size"] == 16

@pytest.mark.asyncio
async def test_end_to_end_policy_modification_affects_chat_gateway(async_client):
    # Acquire admin token
    login_res = await async_client.post("/api/v1/auth/login", json={
        "email": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_PASSWORD
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    salary_prompt = "What is SentinelCorp's executive compensation policy?"

    try:
        # STEP 1: Disable salary policy rule via PUT /api/v1/policies
        disable_res = await async_client.put("/api/v1/policies", json={
            "rules": {"block_employee_salary_queries": False}
        }, headers=headers)
        assert disable_res.status_code == 200
        assert disable_res.json()["rules"]["block_employee_salary_queries"] is False

        # Submit salary prompt to /chat gateway when policy is DISABLED
        chat_res1 = await async_client.post("/api/v1/chat", json={
            "prompt": salary_prompt,
            "llm_provider": "ollama"
        })
        assert chat_res1.status_code == 200
        data1 = chat_res1.json()
        # Verify policy did NOT block when rule was disabled
        assert data1["security_eval"]["verdict"] == "FORWARDED"
        assert data1["security_eval"]["is_malicious"] is False

        # STEP 2: Authenticated admin ENABLES salary policy rule via PUT /api/v1/policies
        enable_res = await async_client.put("/api/v1/policies", json={
            "rules": {"block_employee_salary_queries": True}
        }, headers=headers)
        assert enable_res.status_code == 200
        assert enable_res.json()["rules"]["block_employee_salary_queries"] is True

        # Verify policy persistence safety: block_api_keys must remain True
        assert enable_res.json()["rules"].get("block_api_keys", True) is True

        # STEP 3: Submit the SAME salary prompt again to /chat gateway when policy is ENABLED
        chat_res2 = await async_client.post("/api/v1/chat", json={
            "prompt": salary_prompt,
            "llm_provider": "ollama"
        })
        assert chat_res2.status_code == 200
        data2 = chat_res2.json()
        # Should now be BLOCKED by policy
        assert data2["security_eval"]["verdict"] == "BLOCKED"
        assert data2["security_eval"]["is_malicious"] is True

    finally:
        # STEP 4: Restore original policy
        await async_client.put("/api/v1/policies", json={
            "rules": {"block_employee_salary_queries": True}
        }, headers=headers)
