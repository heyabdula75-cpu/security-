from httpx import ASGITransport, AsyncClient
from app.main import app


async def test_login_error_missing_payload():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/auth/login", json={})

    assert response.status_code == 422
