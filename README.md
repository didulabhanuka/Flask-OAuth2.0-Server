# OAuth2 Authorization Server API Documentation

## Overview

This API provides OAuth2-based authentication and token management for securing API endpoints. The primary functionality includes issuing access tokens using the `client_credentials` and `refresh_token` grant types, validating tokens, and managing clients.

### Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication Flow](#authentication-flow)
3. [Rate Limiting](#rate-limiting)
4. [Error Handling](#error-handling)
5. [Endpoints](#endpoints)
   - [`POST /token`](#post-token)
   - [`GET /api-secure-data`](#get-api-secure-data)
   - [`POST /create-client`](#post-create-client)
6. [Token Management](#token-management)
7. [Client Management](#client-management)

---

## Getting Started

### Prerequisites

- Python 3.8+
- Flask framework
- `authlib`, `ratelimit`, `backoff` libraries

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/your-repo/your-oauth2-server.git
   cd your-oauth2-server
   ```

2. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Server**

   ```bash
   flask run
   ```

### Configuration

- The server uses JSON files (`clients.json` and `tokens.json`) to store client credentials and tokens. These files are located in the current working directory.

---

## Authentication Flow

### Client Credentials Grant

1. **Client Registration**
   - A client registers by calling the `/create-client` endpoint, which generates a `client_id` and `client_secret`.

2. **Token Request**
   - The client requests a token by providing their `client_id` and `client_secret` to the `/token` endpoint with the `client_credentials` grant type.

3. **Accessing Protected Resources**
   - The client uses the issued token to access protected resources by including it in the `Authorization` header.

### Refresh Token Grant

1. **Token Request**
   - The client requests a token using an existing `refresh_token` by calling the `/token` endpoint with the `refresh_token` grant type.

2. **New Token Issued**
   - A new token is issued, and the old token's usage count is reduced. Once the usage count reaches zero, the refresh token is invalidated.

---

## Rate Limiting

- The `/token` endpoint is rate-limited to **10 requests per minute**. If this limit is exceeded, a `429 Too Many Requests` response is returned.

---

## Error Handling

All error responses include both an `error` field and a `message` field providing additional details.

### Common Errors

- **400 Bad Request**
  - **Invalid Request**: The request is missing required parameters or contains invalid values.
  - **Unsupported Grant Type**: The grant type is not supported by the server.

- **401 Unauthorized**
  - **Invalid Client**: The provided `client_id` or `client_secret` is incorrect.
  - **Invalid Token**: The provided token is invalid or expired.

- **429 Too Many Requests**
  - **Rate Limit Exceeded**: The request rate limit has been exceeded.

- **500 Internal Server Error**
  - **Server Error**: An unexpected error occurred on the server.

---

## Endpoints

### `POST /token`

#### Description

Generates a new access token using either `client_credentials` or `refresh_token` grant types.

#### Request Parameters

- **grant_type**: `string` (Required)
  - The type of grant being used. Supported values:
    - `client_credentials`
    - `refresh_token`
- **client_id**: `string` (Required for `client_credentials`)
  - The client identifier.
- **client_secret**: `string` (Required for `client_credentials`)
  - The client secret.
- **refresh_token**: `string` (Required for `refresh_token`)
  - The refresh token issued previously.

#### Responses

- **200 OK**
  - **Description**: Returns a JSON object containing the new access token, refresh token, expiration time, etc.
  - **Response Example**:
    ```json
    {
      "access_token": "abcdef123456",
      "token_type": "bearer",
      "expires_in": 3600,
      "refresh_token": "123456abcdef",
      "scope": "read"
    }
    ```

- **400 Bad Request**
  - **Description**: The request is invalid.
  - **Response Example**:
    ```json
    {
      "error": "unsupported_grant_type",
      "message": "Grant type xyz is not supported."
    }
    ```

- **401 Unauthorized**
  - **Description**: Client authentication failed or invalid/expired refresh token.
  - **Response Example**:
    ```json
    {
      "error": "invalid_client",
      "message": "Client authentication failed."
    }
    ```

- **429 Too Many Requests**
  - **Description**: Rate limit exceeded.
  - **Response Example**:
    ```json
    {
      "error": "too_many_requests",
      "message": "Rate limit exceeded. Please try again later."
    }
    ```

- **500 Internal Server Error**
  - **Description**: An internal error occurred.
  - **Response Example**:
    ```json
    {
      "error": "internal_server_error",
      "message": "An internal server error occurred."
    }
    ```

### `GET /api-secure-data`

#### Description

Accesses a secure endpoint that requires a valid access token.

#### Headers

- **Authorization**: `string` (Required)
  - Bearer token authorization header. Format: `Bearer {access_token}`

#### Responses

- **200 OK**
  - **Description**: Returns a JSON object containing the secure data.
  - **Response Example**:
    ```json
    {
      "data": "This is protected data"
    }
    ```

- **401 Unauthorized**
  - **Description**: Invalid or missing access token.
  - **Response Example**:
    ```json
    {
      "error": "missing_token",
      "message": "Authorization token is missing."
    }
    ```

### `POST /create-client`

#### Description

Creates a new client and returns the `client_id` and `client_secret`.

#### Responses

- **200 OK**
  - **Description**: Returns a JSON object containing the new `client_id` and `client_secret`.
  - **Response Example**:
    ```json
    {
      "client_id": "abcd1234",
      "client_secret": "secret5678"
    }
    ```

- **500 Internal Server Error**
  - **Description**: An internal error occurred while creating the client.
  - **Response Example**:
    ```json
    {
      "error": "internal_server_error",
      "message": "An internal server error occurred while creating the client."
    }
    ```

---

## Token Management

### Token Storage

- Tokens are stored in a JSON file (`tokens.json`).
- Each token is hashed using SHA-256 before storage.
- Access tokens have a default expiration time of 1 hour.
- Refresh tokens have a usage limit of 5 before they are invalidated.

### Token Validation

- Tokens are validated by comparing the hashed version of the provided token with the stored hashed token.
- Access tokens are checked for expiration.
- Refresh tokens are checked for their usage count.

### Token Invalidation

- When a new token is issued, the previous tokens for that client are invalidated (if applicable).

---

## Client Management

### Client Registration

- Clients are registered using the `/create-client` endpoint, which generates and returns a `client_id` and `client_secret`.

### Client Storage

- Client details are stored in a JSON file (`clients.json`).
- Each client has an associated `client_id`, `client_secret`, `grant_type`, and `scope`.

### Client Authentication

- Clients are authenticated using their `client_id` and `client_secret` when requesting tokens.

---

## Contributing

We welcome contributions to this project. Please submit issues or pull requests via GitHub.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
