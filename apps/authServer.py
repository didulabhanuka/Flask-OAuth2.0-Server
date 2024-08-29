from authlib.oauth2.rfc6749 import OAuth2Error, AuthorizationServer
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
import time, logging, json, os, secrets, hashlib, base64
from ratelimit import limits, RateLimitException
from backoff import on_exception, expo

# Dummy storage
tokens = {}

class Client:
    def __init__(self, client_id, client_secret, grant_type, scope):
        self.client_id = client_id
        self.client_secret = client_secret
        self.grant_type = grant_type
        self.scope = scope

    def check_grant_type(self, grant_type):
        return self.grant_type == grant_type

def load_clients_from_file(clients_file):
    if os.path.exists(clients_file):
        try:
            with open(clients_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f'Error decoding JSON from file: {e}')
            return []
    return []

def save_client_to_file(client_data, clients_file):
    try:
        if os.path.exists(clients_file):
            with open(clients_file, 'r') as f:
                clients = json.load(f)
        else:
            clients = []

        clients.append(client_data)

        with open(clients_file, 'w') as f:
            json.dump(clients, f, indent=4)
    except Exception as e:
        logging.error(f'Failed to save client data: {e}')

class MyAuthorizationServer(AuthorizationServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token_generator = self.default_token_generator  # Ensure the default generator is set

    def authenticate_client(self, request, grant_type):
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')

        if grant_type == 'refresh_token':
            # For refresh tokens, client authentication might not be necessary
            # Implement logic to handle refresh tokens without client_id and client_secret
            return None  # Or any appropriate handling for refresh tokens without client authentication

        # For other grant types, ensure client authentication
        if not client_id or not client_secret:
            raise OAuth2Error(error='invalid_client', description='Client authentication failed.')

        clients = load_clients_from_file('clients.json')
        client_data = next((client for client in clients if client['client_id'] == client_id), None)
        if client_data and client_data['client_secret'] == client_secret:
            return Client(client_id, client_secret, client_data.get('grant_type', 'client_credentials'), client_data.get('scope', 'read'))
        
        raise OAuth2Error(error='invalid_client', description='Client authentication failed.')
        
    def save_token(self, token, client, invalidate_previous=False):
        try:
            hashed_token = hashlib.sha256(token['access_token'].encode('utf-8')).hexdigest()

            # Invalidate previous tokens if specified
            if invalidate_previous:
                self.invalidate_previous_tokens(client.client_id)

            tokens[hashed_token] = token
            if 'refresh_token' in token:
                hashed_refresh_token = hashlib.sha256(token['refresh_token'].encode('utf-8')).hexdigest()
                tokens[hashed_refresh_token] = {
                    'token': token,
                    'usage_count': 5  # Set the initial usage limit to 5
                }

        except Exception as e:
            logging.error(f'Failed to save token: {e}')

    def validate_token(self, token, token_type='access'):
        try:
            hashed_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
            token_info = tokens.get(hashed_token)

            if token_info and time.time() < token_info['expires_at']:
                return token_info
            return None
        except Exception as e:
            logging.error(f'Failed to validate {token_type} token: {e}')
            return None

    def reduce_refresh_token_usage(self, token):
        try:
            hashed_refresh_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
            if hashed_refresh_token in tokens:
                tokens[hashed_refresh_token]['usage_count'] -= 1
                if tokens[hashed_refresh_token]['usage_count'] <= 0:
                    # If usage count is zero or less, remove the refresh token
                    del tokens[hashed_refresh_token]
        except Exception as e:
            logging.error(f'Failed to reduce refresh token usage: {e}')

    def invalidate_previous_tokens(self, client_id):
        try:
            for token_hash, token_info in list(tokens.items()):
                if token_info['client_id'] == client_id:
                    del tokens[token_hash]
        except Exception as e:
            logging.error(f'Failed to invalidate previous tokens: {e}')

    def default_token_generator(self, client, grant_type, *args, **kwargs):
        random_bytes = secrets.token_bytes(32)
        access_token = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        refresh_token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        expires_in = 3600
        expires_at = time.time() + expires_in
        scope = client.scope if client else 'read'
        
        return {
            'access_token': access_token,
            'token_type': 'bearer',
            'expires_in': expires_in,
            'expires_at': expires_at,
            'refresh_token': refresh_token,
            'scope': scope,
            'client_id': client.client_id  # Associate token with client_id
        }

    def generate_token(self, client, grant_type, *args, **kwargs):
        # Ensure token generator is set before calling it
        if not self.token_generator:
            self.token_generator = self.default_token_generator
        return self.token_generator(client, grant_type, *args, **kwargs)

    def handle_new_token(self, client, grant_type):
        token = self.generate_token(client, grant_type)
        self.save_token(token, client, invalidate_previous=True)
        return token

    def handle_refresh_token(self, refresh_token):
        token_info = self.validate_token(refresh_token, token_type='refresh')
        if not token_info:
            return None

        self.reduce_refresh_token_usage(refresh_token)
        new_token = self.generate_token(token_info['client_id'], grant_type='refresh_token')
        self.save_token(new_token, token_info['client_id'])
        return new_token


authorization_server = MyAuthorizationServer()
authorization_server.register_grant(ClientCredentialsGrant)
