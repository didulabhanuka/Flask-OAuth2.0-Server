# Public OAuth2 API Documentation

## Overview
This documentation provides details on the implementation and usage of the Public OAuth2 API, designed to securely issue and validate access tokens and refresh tokens for authorized clients. It includes token-based authentication and permission-based access control.

---

## Table of Contents
1. **Getting Started**
2. **Endpoints**
3. **Authentication and Token Management**
4. **Permissions and Scopes**
5. **Rate Limiting**
6. **Error Handling**
7. **Security Considerations**

---

## 1. Getting Started

### Base URL
The API is hosted at the following base URL:  
`/public-api/OAuth/`

### Required Headers
Include the following headers in your API requests:
- `Authorization`: `Bearer <access_token>`

### Prerequisites
- You must register as a client with the service to obtain a `client_id` and `client_secret`.
- Use these credentials to authenticate with the `/token` endpoint and receive your access token.

---

## 2. Endpoints

### `/token`
**Method**: `POST`  
**Description**: Issues a new access token and refresh token for a client.  
**Rate Limit**: 200 requests per day.

**Request Parameters**:  
- `client_id` (string, required): The client's unique identifier.  
- `client_secret` (string, required): The secret associated with the client.  

**Response**:  
```json
{
  "access_token": "your_access_token",
  "token_type": "bearer",
  "expires_in": 3600,
  "expires_at": 1707062400,
  "refresh_token": "your_refresh_token",
  "scope": "read"
}
```

---

### `/token/refresh`
**Method**: `POST`  
**Description**: Refreshes an expired access token using a valid refresh token.  

**Request Parameters**:  
- `refresh_token` (string, required): The refresh token received during initial token issuance.

**Response**:  
```json
{
  "access_token": "new_access_token",
  "token_type": "bearer",
  "expires_in": 3600,
  "expires_at": 1707066000,
  "refresh_token": "new_refresh_token",
  "scope": "read"
}
```

---

## 3. Authentication and Token Management

### Client Authentication
Clients authenticate using the `client_credentials` grant type:
1. Submit the `client_id` and `client_secret` to `/token`.
2. The server validates the credentials and returns a JWT access token and a refresh token.

### Token Expiration
- Access tokens expire after **1 hour**.
- Refresh tokens can be used to request a new access token.

---

## 4. Permissions and Scopes

### Scopes
Scopes define the level of access granted to the client:
- `read`: Read-only access to resources.

### Permissions
Clients can have additional permissions such as:
- `read`: Access to read data.
- `write`: Access to modify data.

---

## 5. Rate Limiting

Each client is limited to **200 requests per day** for token generation.

---

## 6. Error Handling

### Common Errors
| Error Code          | Description                                      | HTTP Status Code |
|---------------------|--------------------------------------------------|------------------|
| `invalid_client`    | Client authentication failed.                    | 400              |
| `invalid_grant`     | Refresh token is invalid or expired.             | 400              |
| `insufficient_scope`| Client lacks the required scope.                 | 403              |
| `token_expired`     | Access token has expired.                        | 401              |
| `invalid_token`     | Token is invalid or revoked.                     | 401              |

### Example Error Response
```json
{
  "error": "invalid_client",
  "description": "Client authentication failed."
}
```

---

## 7. Security Considerations

### 7.1 Token Security
- Always keep `client_id` and `client_secret` confidential.
- Use secure HTTPS connections to transmit sensitive data.
- Access tokens are JWTs signed with HMAC SHA-256, ensuring integrity and authenticity.

### 7.2 Database
- All sensitive data (e.g., refresh tokens) is hashed using SHA-256 before storage.

### 7.3 Configurations
#### Secure the App Secret Key
- Update the `SECRET_KEY` in the configuration file (`config.py`) with a strong, secure value. 
- **Uncomment the SECRET_KEY in `config.py`** to activate secure token signing:
```python
# SECRET_KEY = os.getenv('SECRET_KEY', 'your_security_key_here')
```

### 7.4 Logging
- Errors and sensitive actions are logged with appropriate caution. Avoid logging sensitive details such as `client_secret` or token values.

--- 

For further assistance, please contact the API support team.
