import functions_framework
from flask import jsonify
from jwcrypto import jwk
from datetime import datetime
import json
from functools import wraps

# Load public key from file
with open("public.pem", "r") as f:
    PUBLIC_KEY = f.read()

# Key ID (must match the `kid` in JWTs issued)
KEY_ID = "excel-reorder"
ALGORITHM = 'RS256'
USAGE = 'sig'
KEY_TYPE = 'RSA'
# Prepare JWK from public key once (avoid recalculating per request)
try:
    jwk_key = jwk.JWK.from_pem(PUBLIC_KEY.encode())
    jwk_data = jwk_key.export_public(as_dict=True)
    jwk_data.update({
        "kid": KEY_ID,
        "alg": ALGORITHM,
        "use": USAGE,
        "kty": KEY_TYPE
    })
    JWKS = {"keys": [jwk_data]}
except Exception as e:
    print(f" Error loading public key: {e}")
    JWKS = {"keys": []}

def get_cors_headers(request):
    # Get the origin from the request
    origin = request.headers.get('Origin', '*')
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        'Access-Control-Allow-Credentials': 'true'
    }
def standard_error_response(request_id, timestamp=None, status=400, message="Bad Request",
                            code="INVALID_REQUEST", error_message="Something went wrong.", details=None):
     # We can alter below to include any alterations to the response structure
    return {
        "meta": {
            "requestId": request_id,
            "timestamp": timestamp or datetime.utcnow().isoformat() + "Z",
            "status": status,
            "message": message,
            "version": "v1"
        },
        "data": None,
        "error": {
            "code": code,
            "message": error_message,
            "details": details or []
        }
    }
def cors_enabled(f):
    """Enhanced CORS Decorator"""
    @wraps(f)
    def decorated_function(request):
        # Dynamic CORS Headers
        cors_headers = get_cors_headers(request)

        # Handle CORS Preflight Requests
        if request.method == 'OPTIONS':
            return ('', 204, cors_headers)
        
        try:
            # Call the original function
            result = f(request)
            
            # Add CORS headers to response
            if isinstance(result, tuple):
                if len(result) == 2:
                    body, status = result
                    return body, status, cors_headers
                elif len(result) == 3:
                    body, status, headers = result
                    headers.update(cors_headers)
                    return body, status, headers
            return result, 200, cors_headers
        
        except Exception as e:
            error_response = jsonify(standard_error_response(
                "UNKNOWN", status=500, 
                message="Internal Server Error",
                code="CORS_ERROR", 
                error_message=str(e)
            ))
            return error_response, 500, cors_headers
    
    return decorated_function

@functions_framework.http
@cors_enabled
def jwks_well_known(request):
    """
    Well-known JWKS endpoint
    Required for GCP API Gateway (must end with /.well-known/jwks.json)
    """
    return jsonify(JWKS), 200
