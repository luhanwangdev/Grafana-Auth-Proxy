from pydantic import BaseModel, Field
from typing import Optional


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example='kas')
    password: str = Field(..., min_length=3, max_length=50, example='password')


class LoginResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    message: str
    user_info: Optional[str] = None


class ValidateResponse(BaseModel):
    is_validated: bool


class SignUpRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=3, max_length=50)

    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "password": "secure_password",
            }
        }


class SignUpResponse(BaseModel):
    success: bool
    grafana_user_id: int
    grafana_folder_uid: str
    user_info: Optional[str] = None
