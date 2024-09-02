from flask import request, jsonify
from . import blueprint
from .authServer import authorization_server, save_client_to_file
import secrets, logging, os, json
from ratelimit import limits, RateLimitException
from backoff import on_exception, expo
from authlib.oauth2.rfc6749 import OAuth2Error

# Path to the JSON file where client details will be saved
clients_file = os.path.join(os.getcwd(), 'clients.json')

# Implement rate limiting for the token endpoint
@on_exception(expo, RateLimitException, max_tries=3)
@limits(calls=10, period=60)  # 10 requests per minute
@blueprint.route('/token', methods=['POST'])
def token():
    try:
        grant_type = request.form.get('grant_type')
        refresh_token = request.form.get('refresh_token')
        client_id = request.form.get('client_id') 

        if grant_type == 'refresh_token':
            new_token = authorization_server.handle_refresh_token(refresh_token, client_id)
            if not new_token:
                return jsonify({'error': 'invalid_or_expired_refresh_token'}), 401
            return jsonify(new_token)

        client = authorization_server.authenticate_client(request, grant_type)
        if not client:
            return jsonify({'error': 'invalid_client'}), 401

        new_token = authorization_server.handle_new_token(client, grant_type)
        return jsonify(new_token)

    except RateLimitException:
        return jsonify({'error': 'too_many_requests'}), 429
    except OAuth2Error as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logging.error(f'Unexpected error in token endpoint: {e}')
        return jsonify({'error': 'internal_server_error'}), 500


@blueprint.route('/api-secure-data', methods=['GET'])
def secure_data():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'missing_token'}), 401

    token = token.split(' ')[1]
    token_info = authorization_server.validate_token(token)
    if not token_info:
        return jsonify({'error': 'invalid_token'}), 401

    return jsonify({'data': 'This is protected data'})


@blueprint.route('/create-client', methods=['POST'])
def create_client():
    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)

    client_data = {"client_id": client_id, "client_secret": client_secret}
    save_client_to_file(client_data, clients_file)

    return jsonify(client_data)