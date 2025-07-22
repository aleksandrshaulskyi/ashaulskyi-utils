from typing import Any, Callable

from functools import wraps
from http import HTTPStatus
from os import getenv

from fastapi.responses import JSONResponse

from jwt import decode


def authenticate_and_get_user(jwt_keyword: str, id_keyword: str) -> JSONResponse | None:
    '''
    The decorator that sets user id into request state.

    :param jwt_keyword: Specifies the name of a key of your secret in the .env file.
    :param id_keyword: Specifies the key of a user id stored in a JWT payload.
    '''

    def decorator_wrapper(func: Callable) -> Callable:

        @wraps(func)
        async def function_wrapper(*args: Any, **kwargs: Any) -> Any:
            if (key := getenv(jwt_keyword)) is None:
                raise KeyError('You must specify a secret key in an .env file with a keyword KEY')

            request = kwargs.get('request')

            try:
                authorization = request.headers['Authorization']
            except KeyError:
                error_content = 'No authorization header provided.'
                return JSONResponse(content=error_content, status_code=HTTPStatus.UNAUTHORIZED)
            
            try:
                prefix, token = authorization.split(' ')
            except ValueError:
                error_content = 'Invalid authorization header format.'
                return JSONResponse(content=error_content, status_code=HTTPStatus.UNAUTHORIZED)

            try:
                decoded_token = decode(jwt=token, key=key, algorithms='HS256')
            except Exception as e:
                error_content = f'Validation failerd due: {e}'
                return JSONResponse(content=error_content, status_code=HTTPStatus.UNAUTHORIZED)
            
            uid = decoded_token.get(id_keyword)

            request.state.uid = uid

            return await func(*args, **kwargs)
        
        return function_wrapper
    
    return decorator_wrapper
