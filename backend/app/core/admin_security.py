# app/core/admin_security.py
"""
Admin Authentication and Security Utilities.

Role-based authentication for admin users.
Uses unified 'users' collection with role field.
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

# Reuse the same secret key and algorithm
SECRET_KEY = "this_is_my_semester_project"
ALGORITHM = "HS256"
ADMIN_TOKEN_EXPIRE_MINUTES = 480  # 8 hours for admin sessions

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for admin routes
oauth2_admin_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/admin/login",
    auto_error=True
)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def create_admin_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT token for admin user.
    Uses role-based authentication with role: "admin" in payload.
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ADMIN_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "role": "admin",  # Role-based access
        "iat": datetime.utcnow()
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_admin_token(token: str) -> dict:
    """
    Decode and validate admin JWT token.
    Raises HTTPException if token is invalid or not an admin token.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Verify this is an admin token (role-based check)
        if payload.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )

        admin_id = payload.get("id")
        email = payload.get("email")

        if admin_id is None or email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )

        return payload

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate admin credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_admin(token: str = Depends(oauth2_admin_scheme)) -> dict:
    """
    Dependency to get the current authenticated admin user.
    Validates that the user has role="admin".

    Usage:
        @router.get("/admin/dashboard")
        async def dashboard(admin: dict = Depends(get_current_admin)):
            admin_id = admin["id"]
            admin_email = admin["email"]
    """
    payload = decode_admin_token(token)
    return {
        "id": payload.get("id"),
        "email": payload.get("email"),
        "role": "admin"
    }


async def require_admin(token: str = Depends(oauth2_admin_scheme)) -> dict:
    """
    Alias for get_current_admin - ensures admin role.
    Use this dependency to protect admin-only routes.
    """
    return await get_current_admin(token)


async def require_user_role(token: str = Depends(oauth2_admin_scheme)) -> dict:
    """
    Dependency that requires user role (not admin).
    Validates that the user has role="user".
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("role") != "user":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User access required"
            )

        return {
            "id": payload.get("id"),
            "email": payload.get("email"),
            "role": "user"
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_client_ip(request: Request) -> str:
    """Extract client IP from request headers"""
    # Check for forwarded IP (if behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fallback to direct client
    if request.client:
        return request.client.host

    return "unknown"


def get_user_agent(request: Request) -> str:
    """Extract User-Agent from request headers"""
    return request.headers.get("User-Agent", "unknown")
