from functools import wraps
from http import HTTPStatus
from os import getenv

from fastapi.responses import JSONResponse

from jwt import decode


def authenticate_and_get_user(func):

    @wraps(func)
    async def wrapper(*args, **kwargs):
        if (key := getenv('KEY')) is None:
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
        
        uid = decoded_token.get('uid')

        request.state.uid = uid

        response = await func(*args, **kwargs)

        return response

    return wrapper
