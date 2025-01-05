import aiomysql
import os
import asyncio
from contextvars import ContextVar
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

DB_CONFIG = {
    'host': os.getenv('MYSQL_HOST', '127.0.0.1'),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', 'password'),
    'db': os.getenv('MYSQL_DATABASE', 'auth'),
    'loop': asyncio.get_event_loop()
}


async def get_db():
    conn = await aiomysql.connect(**DB_CONFIG)
    try:
        yield conn
    finally:
        conn.close()
