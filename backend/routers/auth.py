"""
routers/auth.py — Auth validation using Supabase JWT.

The frontend handles login via Supabase Auth JS SDK.
The backend only needs to verify the JWT on protected routes.
This router exposes a /me endpoint for session validation.
"""
from fastapi import APIRouter, Header, HTTPException
from supabase import create_client
from config import settings

router = APIRouter()

def get_supabase():
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)

@router.get("/me")
async def get_current_user(authorization: str = Header(...)):
    """Validate Supabase JWT and return user info."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.split(" ", 1)[1]

    try:
        supabase = get_supabase()
        user = supabase.auth.get_user(token)
        return {"id": user.user.id, "email": user.user.email}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
