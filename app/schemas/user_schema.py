from pydantic import BaseModel, EmailStr
from typing import Optional


class UserLogin(BaseModel):
    username: str
    password: str
