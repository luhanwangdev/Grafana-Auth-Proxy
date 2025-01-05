from dataclasses import dataclass
import uuid
from ..excpetions import *
import bcrypt


@dataclass
class User:
    id: str
    username: str
    password: str
    grafana_account: str = None

    @classmethod
    def create_new(cls, username: str, password: str, grafana_account: str) -> "User":
        id = str(uuid.uuid4())
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        return cls(
            id=id,
            username=username,
            password=hashed_password,
            grafana_account=grafana_account
        )
