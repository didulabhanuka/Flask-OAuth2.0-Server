import json
import os
import hashlib
import base64
import secrets
import time
import logging
from authlib.oauth2.rfc6749 import OAuth2Error, AuthorizationServer
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from ratelimit import limits, RateLimitException
from backoff import on_exception, expo

# Path to the JSON file where tokens will be saved
tokens_file = os.path.join(os.getcwd(), 'tokens.json')

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

def load_tokens_from_file(tokens_file):
    if os.path.exists(tokens_file):
        try:
            with open(tokens_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f'Error decoding JSON from file: {e}')
            return {}
    return {}

def save_tokens_to_file(tokens, tokens_file):
    try:
        with open(tokens_file, 'w') as f:
            json.dump(tokens, f, indent=4)
    except Exception as e:
        logging.error(f'Failed to save tokens: {e}')

class MyAuthorizationServer(AuthorizationServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token_generator = self.default_token_generator  # Ensure the default generator is set

    def authenticate_client(self, request, grant_type):
        # Extract client credentials from the request
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')

        # Handle refresh token grant type
        if grant_type == 'refresh_token':
            # For refresh tokens, client authentication might not be necessary
            return None
        
        # Handle client credentials grant type
        if grant_type == 'client_credentials':
            # Ensure client credentials are provided
            if not client_id or not client_secret:
                raise OAuth2Error(
                    error='invalid_client',
                    description='Client authentication failed. Both client_id and client_secret are required.'
                )

            # Load client data from the file
            clients = load_clients_from_file('clients.json')

            # Find the client matching the provided client_id
            client_data = next(
                (client for client in clients if client['client_id'] == client_id),
                None
            )

            # Validate client credentials
            if client_data and client_data['client_secret'] == client_secret:
                # Create and return a Client object with the retrieved details
                return Client(
                    client_id,
                    client_secret,
                    client_data.get('grant_type', 'client_credentials'),
                    client_data.get('scope', 'read')
                )
            
            # Raise error if client credentials are invalid
            raise OAuth2Error(
                error='invalid_client',
                description='Client authentication failed. Invalid client_id or client_secret.'
            )
        
        # Handle unknown or unsupported grant types
        raise OAuth2Error(
            error='unsupported_grant_type',
            description=f'Grant type {grant_type} is not supported.'
        )

    def save_token(self, token, client, invalidate_previous=False):
        try:
            tokens = load_tokens_from_file(tokens_file)
            client_id = client.client_id
            hashed_access_token = hashlib.sha256(token['access_token'].encode('utf-8')).hexdigest()
            hashed_refresh_token = hashlib.sha256(token['refresh_token'].encode('utf-8')).hexdigest()

            if invalidate_previous:
                self.invalidate_previous_tokens(client_id, tokens)

            if client_id not in tokens:
                tokens[client_id] = []

            token_entry = {
                "client_id": client_id,
                "access_token": hashed_access_token,  # Store the hashed access token
                "refresh_token": hashed_refresh_token,  # Store the hashed refresh token
                "expires_at": token['expires_at'],
                "scope": token.get('scope', 'read'),
                "usage_count": 5 if 'refresh_token' in token else 0
            }

            tokens[client_id].append(token_entry)

            save_tokens_to_file(tokens, tokens_file)
        except Exception as e:
            logging.error(f'Failed to save token: {e}')

    def validate_token(self, token, token_type='access'):
        try:
            hashed_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
            tokens = load_tokens_from_file(tokens_file)

            for client_id, token_entries in tokens.items():
                for entry in token_entries:
                    logging.error(f"Checking token entry: {entry}")
                    if token_type == 'access' and entry['access_token'] == hashed_token:
                        if time.time() < entry['expires_at']:
                            return entry
                    elif token_type == 'refresh' and entry['refresh_token'] == hashed_token:
                        if entry['usage_count'] > 0:
                            return entry
            return None
        except Exception as e:
            logging.error(f'Failed to validate {token_type} token: {e}')
            return None

    def reduce_refresh_token_usage(self, token):
        try:
            hashed_refresh_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
            tokens = load_tokens_from_file(tokens_file)

            for client_id, token_entries in tokens.items():
                for entry in token_entries:
                    if entry['refresh_token'] == hashed_refresh_token:
                        entry['usage_count'] -= 1
                        if entry['usage_count'] <= 0:
                            token_entries.remove(entry)
                        save_tokens_to_file(tokens, tokens_file)
                        return
        except Exception as e:
            logging.error(f'Failed to reduce refresh token usage: {e}')

    def invalidate_previous_tokens(self, client_id, tokens):
        try:
            if client_id in tokens:
                del tokens[client_id]
                save_tokens_to_file(tokens, tokens_file)
        except Exception as e:
            logging.error(f'Failed to invalidate previous tokens: {e}')

    def default_token_generator(self, client, grant_type, *args, **kwargs):
        try:
            logging.debug("Inside default_token_generator.")
            random_bytes = secrets.token_bytes(32)
            access_token = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
            refresh_token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
            expires_in = 3600
            expires_at = time.time() + expires_in
            scope = 'read'

            token = {
                'access_token': access_token,
                'token_type': 'bearer',
                'expires_in': expires_in,
                'expires_at': expires_at,
                'refresh_token': refresh_token,
                'scope': scope
            }

            logging.debug(f"Generated token: {token}")

            return token
        except Exception as e:
            logging.error(f"Error in token generation: {e}")
            return None
    
    def generate_token(self, client, grant_type, *args, **kwargs):
        if not self.token_generator:
            self.token_generator = self.default_token_generator
        return self.token_generator(client, grant_type, *args, **kwargs)

    def handle_new_token(self, client, grant_type):
        token = self.generate_token(client, grant_type)
        self.save_token(token, client, invalidate_previous=True)
        return token

    def handle_refresh_token(self, refresh_token, provided_client_id):
        try:
            # Load tokens from file
            tokens = load_tokens_from_file(tokens_file)
            
            # Compute hash for the provided refresh token
            refresh_token_hash = hashlib.sha256(refresh_token.encode('utf-8')).hexdigest()
            
            logging.error(f'refresh_token_hash: {refresh_token_hash}')

            # Check if the provided client_id exists in the tokens
            if provided_client_id in tokens:
                token_entries = tokens[provided_client_id]

                # Directly access the 'refresh_token' key value
                for entry in token_entries:
                    if entry.get('refresh_token') == refresh_token_hash:
                        # Ensure the refresh token is not mistakenly used as an access token
                        if refresh_token == entry.get('access_token'):
                            logging.error(f'Refresh token is mistakenly used as an access token. Token generation aborted.')
                            return {'error': 'invalid_refresh_token_usage'}

                        logging.error(f'Refresh token matched: {refresh_token} and {refresh_token_hash} for client_id: {provided_client_id}')
                        
                        # Generate a new token
                        new_token = self.default_token_generator(None, grant_type='refresh_token')
                        
                        if new_token is None:
                            logging.error("Token generation returned None.")
                            return {'error': 'token_generation_failed'}
                        
                        # Update the new token with access token and client_id
                        new_token['access_token'] = refresh_token
                        new_token['client_id'] = provided_client_id
                        
                        logging.error(f'New token info before saving: {new_token}')
                        
                        # Save the new token
                        self.save_token(new_token, client=None)
                        
                        # Reduce the usage count of the refresh token
                        self.reduce_refresh_token_usage(refresh_token)
                        
                        logging.debug(f'New token successfully generated and saved.')
                        
                        return new_token

            # If no matching refresh token is found
            logging.error(f'Refresh token does not match any records for client_id: {provided_client_id}.')
            return {'error': 'invalid_or_expired_refresh_token'}

        except Exception as e:
            logging.error(f'Error in handle_refresh_token: {e}')
            return {'error': 'internal_server_error'}

# Initialize the authorization server and register the grant type
authorization_server = MyAuthorizationServer()
authorization_server.register_grant(ClientCredentialsGrant)
