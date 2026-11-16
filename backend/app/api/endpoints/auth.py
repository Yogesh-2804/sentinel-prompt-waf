from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.db.repositories import UserRepository
from app.models.domain import User
from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.config import settings
from app.api.schemas import UserRegisterRequest, UserLoginRequest, TokenResponse, UserResponse
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(req: UserRegisterRequest, db: AsyncSession = Depends(get_db)):
    repo = UserRepository(db)
    existing_user = await repo.get_by_email(req.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is already registered")

    user = User(
        email=req.email,
        hashed_password=get_password_hash(req.password),
        full_name=req.full_name,
        role=req.role or "admin"
    )
    new_user = await repo.create(user)
    return UserResponse(id=new_user.id, email=new_user.email, full_name=new_user.full_name, role=new_user.role)


@router.post("/login", response_model=TokenResponse)
async def login_user(req: UserLoginRequest, db: AsyncSession = Depends(get_db)):
    # Check default admin credentials
    if req.email == settings.ADMIN_USERNAME or req.email == "admin@sentinel.corp":
        if req.password == settings.ADMIN_PASSWORD:
            access_token = create_access_token(subject=settings.ADMIN_USERNAME, expires_delta=None)
            return TokenResponse(access_token=access_token, token_type="bearer", expires_in_minutes=60)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect admin username or password",
                headers={"WWW-Authenticate": "Bearer"}
            )

    # Check DB users
    repo = UserRepository(db)
    user = await repo.get_by_email(req.email)
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token = create_access_token(subject=user.email)
    return TokenResponse(access_token=access_token, token_type="bearer", expires_in_minutes=60)


@router.get("/me", response_model=UserResponse)
async def get_my_profile(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return UserResponse(id=current_user.id, email=current_user.email, full_name=current_user.full_name, role=current_user.role)
