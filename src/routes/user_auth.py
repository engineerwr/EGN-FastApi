from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from src.model.user_auth import Token
from src.repository.authentication import authenticate_user, create_access_token, get_password_hash
from datetime import datetime, timedelta

app = FastAPI()

@app.get("/token", response_model=Token)
async def get_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario ou Senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    token_expire = timedelta(minutes=30)
    access_token = create_access_token(data={"sub": user.username }, expires_delta=token_expire)
    return {"access_token": access_token, "token_type": "bearer"}
