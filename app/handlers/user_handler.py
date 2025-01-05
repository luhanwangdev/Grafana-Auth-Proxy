from fastapi import FastAPI, HTTPException, Request, Response, Depends, Header
from fastapi.responses import JSONResponse
from typing import Optional
import uvicorn
from ..schemas import api_schema
from ..models import user_models, database
from ..repositories import user_repository
from ..excpetions import *
from aiomysql import Connection
import logging
import traceback
import bcrypt
import jwt
import os
from datetime import datetime, timedelta
import aiohttp

SECRET_KEY = os.getenv('JWT_SECRET')
# GRAFANA_API_KEY = os.getenv('GRAFANA_TOKEN')
GRAFANA_ADMIN_ACCOUNT = os.getenv('GRAFANA_ADMIN_ACCOUNT')
GRAFANA_ADMIN_PASSWORD = os.getenv('GRAFANA_ADMIN_PASSWORD')
GRAFANA_ADMIN_URL = f'http://{GRAFANA_ADMIN_ACCOUNT}:{GRAFANA_ADMIN_PASSWORD}@localhost:3000'
JWT_ALGORITHM = "HS256"
TOEKN_EXPIRE_DAYS = 1


async def login_handler(request: api_schema.LoginRequest,
                        response: Response,
                        conn: Connection = Depends(database.get_db)) -> api_schema.LoginResponse:

    username = request.username
    password = request.password

    try:
        user_data = await user_repository.get_user_by_username(conn=conn, username=username)
        hashed_password = user_data['password']

        is_verified = bcrypt.checkpw(
            password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )

        if not is_verified:
            raise PasswordWrongException

        # login successfully
        user_id_data = {
            "user_id": user_data['id'],
            "username": user_data['username'],
            "grafana_account": user_data['grafana_account']
        }
        token = create_token(user_data=user_id_data)

        response.set_cookie(
            key='token',
            value=token,
            httponly=True,
            secure=True,
            samesite='lax',
            max_age=TOEKN_EXPIRE_DAYS * 24 * 60 * 60
        )

        result = {
            "success": True,
            "token": token,
            "message": 'Login successfully'
        }

        return result

    except Exception as e:
        logging.error(traceback.format_exc())
        raise e


async def validate_handler(request: Request,
                           response: Response) -> api_schema.ValidateResponse:

    try:
        token = request.cookies.get('token')
        if not token:
            raise TokenInvalidError

        payload = verify_token(token=token)

        # set header to grafana
        response.headers['X-GRAFANA-ACCOUNT'] = payload['user']['grafana_account']

        return {
            "is_validated": True
        }

    except Exception as e:
        logging.error(traceback.format_exc())
        raise e


async def signup_handler(request: api_schema.SignUpRequest,
                         response: Response,
                         conn: Connection = Depends(database.get_db)) -> api_schema.SignUpResponse:
    try:
        is_existed = await user_repository.check_username_existed(conn=conn, username=request.username)
        if is_existed:
            raise UserAlreadyExistedException

        user = user_models.User.create_new(
            request.username,
            request.password,
            request.username        # this row for grafana account
        )

        await user_repository.create_user(conn=conn, user=user)

        async with aiohttp.ClientSession() as session:
            grafana_user_id = await create_grafana_user(session=session, username=request.username, password=request.password)
            grafana_folder_uid = await create_grafana_folder(session=session, username=request.username)
            await set_folder_permission(session=session, folder_uid=grafana_folder_uid, user_id=grafana_user_id)

        user_id_data = {
            "user_id": request.username,
            "username": request.password,
            "grafana_account": request.username
        }
        token = create_token(user_data=user_id_data)

        response.set_cookie(
            key='token',
            value=token,
            httponly=True,
            secure=True,
            samesite='lax',
            max_age=TOEKN_EXPIRE_DAYS * 24 * 60 * 60
        )

        return {
            "success": True,
            "grafana_user_id": grafana_user_id,
            "grafana_folder_uid":  grafana_folder_uid,
            "message": "Congratulation!"
        }

    except Exception as e:
        logging.error(f"Unexpected error during signup: {str(e)}")
        logging.error(traceback.format_exc())
        raise e


async def logout_handler(response: Response) -> JSONResponse:
    response.delete_cookie(
        key="session_token",
        path="/",
        secure=True,
        httponly=True
    )

    return JSONResponse(content={'message': 'Logged out successfully'})


def create_token(user_data: dict) -> str:
    """Create JWT session token"""
    expire = datetime.now() + timedelta(days=TOEKN_EXPIRE_DAYS)
    to_encode = {
        "exp": expire,
        "user": user_data,
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Verify JWT session token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid session")


async def create_grafana_user(session: aiohttp.ClientSession, username: str, password: str) -> int:
    # headers = {
    #     'Authorization': f'Bearer {GRAFANA_API_KEY}',
    #     'Content-Type': 'application/json'
    # }

    user_data = {
        'name': username,
        'email': f'{username}@localhost',
        'login': username,
        'password': password
    }

    endpoint = f"{GRAFANA_ADMIN_URL}/api/admin/users"

    async with session.post(endpoint, json=user_data) as response:
        if response.status == 200:
            data = await response.json()
            return data['id']
        else:
            text = await response.text()
            raise Exception(f"Failed to create user: {text}")


async def create_grafana_folder(session: aiohttp.ClientSession, username: str) -> str:
    # headers = {
    #     'Authorization': f'Bearer {GRAFANA_API_KEY}',
    #     'Content-Type': 'application/json'
    # }

    endpoint = f"{GRAFANA_ADMIN_URL}/api/folders"

    folder_data = {
        "title": username
    }

    async with session.post(endpoint, json=folder_data) as response:
        if response.status == 200:
            data = await response.json()
            return data['uid']
        else:
            text = await response.text()
            raise Exception(f"Failed to create folder: {text}")


async def set_folder_permission(session: aiohttp.ClientSession, folder_uid: str, user_id: int):
    # headers = {
    #     'Authorization': f'Bearer {GRAFANA_API_KEY}',
    #     'Content-Type': 'application/json'
    # }

    permissions_data = {
        "items": [
            {
                "role": "Admin",
                "permission": 4
            },
            {
                "role": "Viewer",
                "permission": 0
            },
            {
                "role": "Editor",
                "permission": 0
            },
            {
                "userId": user_id,
                "permission": 2     # 4 = Admin, 2 = Editor, 1 = Viewer
            }
        ]
    }

    endpoint = f"{GRAFANA_ADMIN_URL}/api/folders/{folder_uid}/permissions"

    async with session.post(endpoint, json=permissions_data) as response:
        if response.status not in (200, 201):
            text = await response.text()
            raise Exception(f"Failed to set folder permissions: {text}")
        return await response.json()
