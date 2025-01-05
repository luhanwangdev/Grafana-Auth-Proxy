from fastapi import FastAPI, Request, Response, Depends
from fastapi.responses import JSONResponse
from .schemas import api_schema
from .models import user_models, database
from .repositories import user_repository
from .excpetions import *
from .handlers import user_handler
from aiomysql import Connection
import logging
import traceback
import bcrypt
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", 'http://127.0.0.1'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get('/')
async def hello():
    return {
        "message": "hello"
    }


@app.post('/login')
async def login(request: api_schema.LoginRequest, response: Response, conn: Connection = Depends(database.get_db)) -> api_schema.LoginResponse:
    return await user_handler.login_handler(request=request, response=response, conn=conn)


@app.get('/validate')
async def login(request: Request, response: Response) -> api_schema.ValidateResponse:
    return await user_handler.validate_handler(request=request, response=response)


@app.post('/signup')
async def signup(request: api_schema.SignUpRequest, response: Response, conn: Connection = Depends(database.get_db)) -> api_schema.SignUpResponse:
    return await user_handler.signup_handler(request=request, response=response, conn=conn)


@app.get('/logout')
async def logout(response: Response) -> JSONResponse:
    return await user_handler.logout_handler(response=response)
