from datetime import datetime, timedelta
import hashlib
import base64
import os
from typing import Annotated
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from schemas import UserCreate, DecodedToken
from models import User
from config import get_settings


ALGORITHM = "HS256"
SECRET_KEY = get_settings().secret_key

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def create_user(db: Session, user_create: UserCreate):
    existing_user = db.query(User).filter(User.user_name == user_create.user_name).first()
    if existing_user:
        raise ValueError("User name already exists")
    
    salt = base64.b64encode(os.urandom(32))
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        user_create.password.encode('utf-8'),
        salt,
        100000
    ).hex()
    new_user = User(
        user_name=user_create.user_name,
        password=hashed_password,
        salt=salt.decode()
    )
    db.add(new_user)
    db.commit()
    return new_user


def authenticate_user(db: Session, user_name: str, password: str):
    user = db.query(User).filter(User.user_name == user_name).first()
    if user is None:
        return None
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        user.salt.encode(),
        100000
    ).hex()
    if user.password != hashed_password:
        return None
    
    return user

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    expires = datetime.now() + expires_delta
    payload = {"sub": username, "user_id": user_id, "exp": expires}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_name = payload.get("sub")
        user_id = payload.get("user_id")
        if user_name is None or user_id is None:
            return None
        return DecodedToken(username=user_name, user_id=user_id)
    except JWTError:
        return JWTError