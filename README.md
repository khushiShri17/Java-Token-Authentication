# Token Authentication System

A production-ready JWT authentication system built with Java, Spring Boot, MongoDB, and Spring Security — featuring multi-device session management, email verification, account lockout, and role-based authorization.

[![Java](https://img.shields.io/badge/Java-17+-ED8B00.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3-6DB33F.svg)](https://spring.io/projects/spring-boot)
[![MongoDB](https://img.shields.io/badge/MongoDB-4.4+-47A248.svg)](https://www.mongodb.com/)
[![JWT](https://img.shields.io/badge/JWT-JJWT%200.12-000000.svg)](https://github.com/jwtk/jjwt)

## Features

- **User Authentication**
  - Secure registration with email verification
  - Login with JWT tokens (access + refresh tokens)
  - Password hashing with BCrypt (10 rounds)
  - Token rotation on refresh for enhanced security

- **Multi-Device Session Management**
  - Device tracking and limiting (configurable, default: 2 devices)
  - Active sessions viewing and management
  - Single device logout
  - Logout from all devices except current
  - Device (User-Agent) and IP tracking

- **Authorization**
  - Role-based access control (admin/user) via `@PreAuthorize`
  - JWT filter chain with Spring Security
  - Token blacklisting for secure logout (TTL auto-cleanup)

- **Password Management**
  - Forgot password with email reset link
  - Secure password reset with 10-minute expiring tokens
  - Strong password validation via custom `@StrongPassword` annotation

- **Account Security**
  - Per-user account lockout after 5 failed login attempts (30-minute lock)
  - Per-IP rate limiting on all public endpoints
  - Input validation with Jakarta Bean Validation
  - HTTP-only, Secure, SameSite=Strict cookies
  - CORS configuration
  - Generic responses on forgot-password to prevent user enumeration

## Tech Stack

| Technology | Purpose |
|---|---|
| **Java 17+** | Language |
| **Spring Boot 3.3** | Application framework |
| **Spring Security** | Authentication & authorization filter chain |
| **Spring Data MongoDB** | Database access with auto-generated queries |
| **JJWT 0.12** | JWT token creation and verification |
| **Bucket4j** | In-memory token-bucket rate limiting |
| **Spring Boot Mail** | Email sending (verification, password reset) |
| **Jakarta Validation** | Input validation with annotations |
| **Lombok** | Boilerplate reduction |
| **BCrypt** | Password hashing |
| **Maven** | Build tool |

## Project Structure

```
src/main/java/com/auth/tokensystem/
├── TokenAuthenticationSystemApplication.java
├── config/
│   ├── AppProperties.java              # @ConfigurationProperties — all custom config
│   └── SecurityConfig.java             # SecurityFilterChain, CORS, BCrypt bean
├── security/
│   ├── JwtTokenProvider.java           # Generate/validate access & refresh JWTs
│   ├── JwtAuthenticationFilter.java    # OncePerRequestFilter — authenticate every request
│   ├── CustomAuthenticationEntryPoint.java   # 401 JSON responses
│   └── CustomAccessDeniedHandler.java        # 403 JSON responses
├── controller/
│   ├── AuthController.java             # All 13 API endpoints
│   └── HealthCheckController.java      # GET /healthcheck
├── service/
│   ├── AuthService.java / AuthServiceImpl.java         # Core auth logic
│   ├── SessionService.java / SessionServiceImpl.java   # Device/session management
│   ├── EmailService.java / EmailServiceImpl.java       # Verification & reset emails
│   └── TokenBlacklistService.java                      # Access token revocation
├── repository/
│   ├── UserRepository.java
│   ├── RefreshTokenRepository.java
│   └── BlacklistedTokenRepository.java
├── model/
│   ├── User.java                       # User document (with lockout fields)
│   ├── RefreshToken.java               # Session document (TTL index)
│   └── BlacklistedToken.java           # Revoked tokens (TTL index)
├── dto/
│   ├── request/                        # RegisterRequest, LoginRequest, etc.
│   └── response/                       # ApiResponse<T>, UserResponse, SessionResponse
├── validation/
│   ├── StrongPassword.java             # Custom constraint annotation
│   └── StrongPasswordValidator.java    # Enforces 8+ chars, upper, lower, digit, special
├── ratelimit/
│   ├── RateLimit.java                  # @RateLimit annotation
│   ├── RateLimitInterceptor.java       # Bucket4j-backed interceptor
│   └── RateLimitConfig.java            # Registers interceptor
├── exception/
│   ├── GlobalExceptionHandler.java     # @RestControllerAdvice — unified error handling
│   └── *.java                          # BadRequest, Unauthorized, Conflict, etc.
└── util/
    ├── SecureTokenUtil.java            # Crypto-random hex tokens
    ├── CookieUtil.java                 # ResponseCookie builder (httpOnly, SameSite)
    └── IpAddressUtil.java              # X-Forwarded-For + getRemoteAddr()
```

## API Endpoints

### Public (no authentication)

| Method | Endpoint | Rate Limit | Description |
|--------|----------|-----------|-------------|
| GET | `/healthcheck` | None | Health check |
| POST | `/api/v1/users/register` | 100/15min | Register new user |
| POST | `/api/v1/users/login` | 5/15min | Login |
| GET | `/api/v1/users/verify/{token}` | 100/15min | Verify email |
| POST | `/api/v1/users/forgot-password` | 100/15min | Request password reset |
| PUT | `/api/v1/users/reset-password/{token}` | 100/15min | Reset password |
| POST | `/api/v1/users/refresh-token` | 20/15min | Refresh access token |

### Protected (JWT required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/profile` | Get user profile |
| GET | `/api/v1/users/sessions` | List active sessions |
| POST | `/api/v1/users/logout` | Logout current device |
| POST | `/api/v1/users/logout-all-other-devices` | Logout all other devices |
| DELETE | `/api/v1/users/sessions/{sessionId}` | Terminate specific session |
| GET | `/api/v1/users/admin` | Admin-only endpoint (requires ADMIN role) |

## Installation & Setup

### Prerequisites

- Java 17+ (`java -version`)
- Maven (`mvn -version`)
- MongoDB running locally or a MongoDB Atlas URI

### Steps

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd Token-Authentication-System-main
   ```

2. **Set environment variables**
   ```bash
   export MONGODB_URI="mongodb://localhost:27017/token-auth"
   export JWT_ACCESS_TOKEN_SECRET="your-secret-key-at-least-32-characters-long"
   export JWT_REFRESH_TOKEN_SECRET="another-secret-key-at-least-32-characters-long"
   export EMAIL_HOST="smtp.mailtrap.io"
   export EMAIL_PORT="587"
   export SMTP_USER="your-smtp-username"
   export SMTP_PASS="your-smtp-password"
   export MAILTRAP_SENDEREMAIL="noreply@example.com"
   ```

3. **Build and run**
   ```bash
   mvn spring-boot:run
   ```

4. **Access the API**
   ```
   http://localhost:5000/healthcheck
   ```

## Usage Examples

### Register
```bash
curl -X POST http://localhost:5000/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "password": "Password1!"}'
```

### Login
```bash
curl -X POST http://localhost:5000/api/v1/users/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "john@example.com", "password": "Password1!"}'
```

### Get Profile (using cookies from login)
```bash
curl http://localhost:5000/api/v1/users/profile -b cookies.txt
```

### Refresh Token
```bash
curl -X POST http://localhost:5000/api/v1/users/refresh-token -b cookies.txt -c cookies.txt
```

### Logout
```bash
curl -X POST http://localhost:5000/api/v1/users/logout -b cookies.txt
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MONGODB_URI` | Yes | — | MongoDB connection string |
| `JWT_ACCESS_TOKEN_SECRET` | Yes | — | Secret for signing access tokens |
| `JWT_REFRESH_TOKEN_SECRET` | Yes | — | Secret for signing refresh tokens |
| `ACCESS_TOKEN_EXPIRESIN` | No | `15m` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRESIN` | No | `7d` | Refresh token lifetime |
| `EMAIL_HOST` | Yes | — | SMTP host |
| `EMAIL_PORT` | No | `587` | SMTP port |
| `SMTP_USER` | Yes | — | SMTP username |
| `SMTP_PASS` | Yes | — | SMTP password |
| `MAILTRAP_SENDEREMAIL` | No | `noreply@example.com` | Sender email address |
| `PORT` | No | `5000` | Server port |
| `MAX_DEVICES_PER_USER` | No | `2` | Max concurrent sessions per user |

## Data Models

### User
| Field | Type | Description |
|-------|------|-------------|
| id | String | MongoDB ObjectId |
| name | String | User's full name |
| email | String | Unique, lowercase |
| password | String | BCrypt hash |
| role | Enum (USER, ADMIN) | Default: USER |
| isVerified | boolean | Email verification status |
| verificationToken | String | Email verification token |
| verificationTokenTime | Instant | Token expiry |
| passwordResetToken | String | Password reset token |
| passwordResetTokenTime | Instant | Token expiry |
| failedLoginAttempts | int | Lockout counter |
| lockoutUntil | Instant | Account lock expiry |
| createdAt / updatedAt | Instant | Timestamps |

### RefreshToken
| Field | Type | Description |
|-------|------|-------------|
| id | String | MongoDB ObjectId |
| token | String | JWT refresh token (unique) |
| user | String | Reference to User id |
| deviceInfo | String | User-Agent string |
| ipAddress | String | Client IP |
| issuedAt / lastUsed | Instant | Timestamps |
| expiresAt | Instant | TTL index — auto-deleted by MongoDB |

### BlacklistedToken
| Field | Type | Description |
|-------|------|-------------|
| id | String | MongoDB ObjectId |
| token | String | Revoked access token (unique) |
| user | String | Reference to User id |
| expiresAt | Instant | TTL index — auto-deleted by MongoDB |

## API Response Format

All endpoints return a consistent JSON shape:

```json
{
  "success": true,
  "message": "User logged in successfully",
  "data": { ... },
  "timestamp": "2026-07-23T10:30:00Z"
}
```

Error responses:
```json
{
  "success": false,
  "message": "Validation errors",
  "errors": {
    "email": "Please enter a valid email",
    "password": "Password must be at least 8 characters..."
  },
  "timestamp": "2026-07-23T10:30:00Z"
}
```

## Security Measures

| Measure | Implementation |
|---------|---------------|
| Password hashing | BCrypt with 10 salt rounds |
| JWT tokens | Short-lived access (15m) + long-lived refresh (7d) with rotation |
| Token blacklisting | MongoDB collection with TTL auto-cleanup |
| Cookie security | httpOnly, Secure (production), SameSite=Strict |
| Rate limiting | Bucket4j token-bucket algorithm per IP |
| Account lockout | 5 failed attempts → 30-minute lock (per user) |
| Input validation | Jakarta Bean Validation + custom `@StrongPassword` |
| User enumeration prevention | Generic responses on forgot-password |
| CORS | Configured allowed origins, methods, headers |
| Session management | Device limit enforcement, session tracking |
