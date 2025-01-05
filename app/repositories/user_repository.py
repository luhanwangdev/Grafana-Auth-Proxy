from typing import Optional
from aiomysql import Connection, DictCursor, Error as SQLException
import logging
import traceback
from ..models.user_models import User
from ..excpetions import *


async def check_username_existed(username: str, conn: Connection) -> bool:
    try:
        async with await conn.cursor(DictCursor) as cursor:
            await cursor.execute(
                '''
                SELECT username FROM users
                WHERE username = %s
                ''',
                (username,)
            )
            result = await cursor.fetchone()
            if result:
                return True

        return False

    except SQLException as e:
        logging.error(f"SQLError in get_user_by_username, username: {username}")
        logging.error(traceback.format_exc())
        raise DatabaseError

    except Exception as e:
        logging.error(f"Unexpected error in get_user_by_username, username: {username}")
        logging.error(traceback.format_exc())
        raise e


async def get_user_by_username(username: str, conn: Connection) -> str:
    try:
        async with await conn.cursor(DictCursor) as cursor:
            await cursor.execute(
                '''
                SELECT * FROM users
                WHERE username = %s
                ''',
                (username,)
            )
            result = await cursor.fetchone()
            if result:
                return result

        raise UserNotFoundException

    except UserNotFoundException as e:
        logging.error(f"user not found in get_user_by_username, username: {username}")
        logging.error(traceback.format_exc())
        raise UserNotFoundException

    except SQLException as e:
        logging.error(f"SQLError in get_user_by_username, username: {username}")
        logging.error(traceback.format_exc())
        raise DatabaseError

    except Exception as e:
        raise e


async def create_user(user: User, conn: Connection):
    try:
        async with await conn.cursor(DictCursor) as cursor:
            await cursor.execute(
                '''
                INSERT INTO users
                (id, username, password, grafana_account)
                VALUES
                (%s, %s, %s, %s)
                ''',
                (user.id, user.username, user.password, user.grafana_account)
            )
            await conn.commit()

    except SQLException as e:
        logging.error(f"SQLError in get_user_by_username, username: {user.username}")
        logging.error(traceback.format_exc())
        raise DatabaseError('Database connection failed')

    except Exception as e:
        logging.error(f"Unexpected error in get_user_by_username, username: {user.username}")
        logging.error(traceback.format_exc())
        raise AppException('Something wrong!')
