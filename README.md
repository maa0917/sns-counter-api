# SNS Counter API

A Go HTTP API service designed for microcontroller gadgets to fetch Instagram follower counts. The API uses bearer token
authentication with Firestore backend and returns simple JSON responses optimized for resource-constrained devices.

## Quick Start

### Prerequisites

- Go 1.19 or later
- Google Cloud Project with Firestore enabled
- Service account credentials (for local development)

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Set up environment variables:
   ```bash
   # Create .env file for local development
   echo "GCP_PROJECT_ID=your-project-id" > .env
   
   # Set Google Cloud credentials (if not using GCE)
   export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
   ```

### Running the Server

```bash
# Start server on default port 8080
go run main.go

# Start with custom port
PORT=8081 go run main.go

# Build binary
go build -o sns-counter-api main.go
```

## API Endpoints

### Health Check

```
GET /health
```

Public endpoint for health monitoring.

**Response:**

```json
{
  "status": "ok"
}
```

### Instagram Followers

```
GET /api/instagram/followers
```

Protected endpoint that returns Instagram follower count for authenticated tenant.

**Headers:**

```
Authorization: Bearer sk_live_{tenant_id}_{secret}
```

**Response:**

```json
{
  "count": 1234
}
```

**Error Responses:**

```json
{
  "error": "Authorization header required"
}
{
  "error": "Bearer token required"
}
{
  "error": "Invalid token"
}
```

## Authentication

The API uses bearer token authentication with the following format:

```
sk_live_{tenant_id}_{secret}
```

- `tenant_id`: Unique identifier for the client/device
- `secret`: Secret key that is SHA256 hashed and stored in Firestore

### Token Validation

1. Token format validation
2. Firestore lookup in `tenants` collection
3. SHA256 hash verification of secret
4. Active status check

## Database Schema

### Firestore Collection: `tenants`

Document ID: `tenant_id`

```json
{
  "name": "Device Name",
  "ig_user_id": "instagram_user_id",
  "ig_access_token": "access_token",
  "secret_hash": "sha256_hash_of_secret",
  "is_active": true
}
```

## Testing

```bash
# Test health check
curl http://localhost:8080/health

# Test Instagram followers endpoint
curl -H "Authorization: Bearer sk_live_tenant123_secretkey" \
     http://localhost:8080/api/instagram/followers

# Test authentication failure
curl http://localhost:8080/api/instagram/followers
```

## Architecture

### Single-File Design

The entire API is contained in `main.go` with these key components:

- **bearerTokenMiddleware**: Token validation middleware
- **parseToken**: Bearer token parser
- **validateBearerToken**: Firestore-based token validation
- **instagramFollowersHandler**: Main business logic handler
- **getInstagramFollowers**: Mock data provider

### Environment Detection

- Automatically detects Google Cloud Environment vs local development
- Uses GCE metadata service when running on Google Cloud
- Loads .env file for local development

### Microcontroller Optimization

- Minimal JSON responses for low-memory devices
- Simple GET-only API design
- Standard HTTP status codes
- Easy parsing structure

## Security Features

- SHA256 secret hashing for secure token storage
- Active status checking for API key management
- Structured token format with tenant isolation
- Firestore-based authentication backend

## Development

The project follows a single-file architecture for simplicity while maintaining clear separation of concerns through
well-defined functions and middleware.