import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'udacity-fsnd.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'dev'

## AuthError Exception

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header
#get token auth header
#gets authorization header if it exists and raises auth error otherwise
# verifies that the given header is Bearer type and verifies the token
#raises auth error otherwise
def get_token_auth_header():
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            "code": "invalid_header",
            "description":"Authorization header is expected"
        },401)
    auth_parts = auth.split()
    if auth_parts[0].lower() != "bearer":
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must start with 'Bearer'"
        },401)
    elif len(auth_parts) ==1 :
        raise AuthError({
            "code": "invalid_header",
            "description": "Token not found"
        },401)
    elif len(auth_parts) > 2:
        raise AuthError({
            "code":"invalid_header",
            "description":"Authorization header must be bearer token"
        },401)
    token = auth_parts[1]
    return token



#check permission
# checks if permission is present in payload provided and raises error if there's no permission in the payload
def check_permissions(permission, payload):
    if 'permission' not in payload:
        raise AuthError({
            "code":"unauthorized",
            "description": "Permission not included in payload"
        },403)
    if permission not in payload["permissions"]:
            raise AuthError({
            "code":"unauthorized",
            "description": "Permission not found"
        },403)
    return True


#verify decode jwt
#get the json web token from 'http:udacity-fsnd.auth0.com/.well-known/jwks.json'
# decodes the jwt using the token, RSA key, algorithm, audience and issuer
#raises auth error if no token or if token is not valid
def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    
    jwks = json.loads(jsonurl.read())
    
    unverified_header = jwt.get_unverified_header(token)
    
    rsa_key ={}
    
    if "kid" not in unverified_header:
        raise AuthError({
            "code": "invalid_header",
            "description":"Authorization malformed"
        },401)
    
    for key in jwks["keys"]:
        if key["id"]==unverified_header["kid"]:
            rsa_key = {
                "kty":key["kty"],
                "kid":key["kid"],
                "use":key["use"],
                'n':key["n"],
                "e":key["e"]
            }
        
        if rsa_key:
            
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://"+ AUTH0_DOMAIN+'/'
                )
                return payload
           
            except jwt.ExpiredSignatureError:
                raise AuthError({
                    "code":"token_expired",
                    "description":"Token Expired"
                },401)
           
            except jwt.JWTClaimsError:
                raise AuthError({
                    "code":"invalid_claims",
                    "description":"incorrect claims. Please check the audience and issuer"
                },401)
            
            except Exception:
                raise AuthError({
                    "code":"invalid_header",
                    "description":"Unable to parse authorization token"
                },400)
        
        raise AuthError({
            "code":"invalid_header",
            "description":"Unable to find the appropraite key"
        },400)


# require authentication 

def requires_auth(permission=''):
    def requires_auth_decorator(f):
        
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            
            return f(payload, *args, **kwargs)

        return wrapper
    
    return requires_auth_decorator