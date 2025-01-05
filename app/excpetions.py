from fastapi import HTTPException


class AppException(HTTPException):
    def __init__(self, message: str, status_code: int = 500):
        self.detail = message
        self.status_code = status_code


class UserError(AppException):
    def __init__(self):
        super().__init__("User Error", status_code=400)


class UserNotFoundException(AppException):
    def __init__(self):
        super().__init__("User Not Found", status_code=400)


class UserAlreadyExistedException(AppException):
    def __init__(self):
        super().__init__("User is alreay existed!", status_code=400)


class PasswordWrongException(AppException):
    def __init__(self):
        super().__init__("Password is wrong!", status_code=400)


class DatabaseError(AppException):
    def __init__(self):
        super().__init__("Database Error", status_code=500)


class AuthenticationError(AppException):
    def __init__(self):
        super().__init__("Authentication failed", status_code=401)


class TokenInvalidError(AppException):
    def __init__(self):
        super().__init__("Invalid token", status_code=401)
