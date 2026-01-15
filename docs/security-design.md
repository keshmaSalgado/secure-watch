# SecureWatch – Security Design Specification

## 1. Threat Modeling & Defense-in-Depth

SecureWatch adheres to zero-trust principles and NIST SP 800-92 guidelines for computer security log management.

```
                    ┌───────────────────────────────┐
                    │     Client (Browser/API)      │
                    └──────────────┬────────────────┘
                                   │ HTTPS / TLS 1.3
                                   ▼
                    ┌───────────────────────────────┐
                    │      Nginx / Reverse Proxy    │
                    │ - SSL Offloading              │
                    │ - Rate Limiting               │
                    │ - Security Headers (CSP, HSTS)│
                    └──────────────┬────────────────┘
                                   │
                                   ▼
                    ┌───────────────────────────────┐
                    │      ASP.NET Core Web API     │
                    │ - JWT Bearer Validation       │
                    │ - RBAC Policy Enforcement     │
                    │ - FluentValidation            │
                    │ - Parameterized EF Core (SQLi)│
                    │ - Anti-XSS Sanitization       │
                    └───────┬──────────────┬────────┘
                            │              │
                Internal mTLS/Secret     Strict Connection Pool
                            │              │
                            ▼              ▼
                 ┌───────────────┐  ┌───────────────┐
                 │  Python AI    │  │  PostgreSQL   │
                 │  Microservice │  │  (RLS / Enc)  │
                 └───────────────┘  └───────────────┘
```

---

## 2. Authentication & Credential Management

1. **Password Security**:
   - Identity enforces minimum 10 characters, upper, lower, digit, and special characters.
   - Hashed using ASP.NET Identity's PasswordHasher (PBKDF2 with HMAC-SHA512 and salt).
   - Account lockout triggered after 5 consecutive failed login attempts (15-minute lock duration).
2. **JSON Web Tokens (JWT)**:
   - Signed using HMAC-SHA256 (`HS256`) with a cryptographically strong 512-bit key.
   - Lifetime: 15 minutes.
   - Audience, Issuer, and Expiration validation strictly enforced.
3. **Refresh Tokens**:
   - Crytographically secure random 64-byte token.
   - Tied to user ID, client IP, and creation timestamp.
   - **Rotation**: Whenever a refresh token is used, it is revoked and replaced with a new token.
   - **Revocation Cascade**: If an already revoked token is submitted, all active refresh tokens for that user are revoked immediately (replay attack detection).

---

## 3. Role-Based Access Control (RBAC) Matrix

| Permission | Super Admin | Security Admin | Security Analyst | Auditor |
|---|:---:|:---:|:---:|:---:|
| `dashboard:view` |  |  |  |  |
| `events:view` |  |  |  |  |
| `events:ingest` |  |  | ❌ | ❌ |
| `threats:view` |  |  |  |  |
| `incidents:view` |  |  |  |  |
| `incidents:create` |  |  |  | ❌ |
| `incidents:assign` |  |  | ❌ | ❌ |
| `incidents:update` |  |  |  | ❌ |
| `incidents:resolve`|  |  |  | ❌ |
| `intel:query` |  |  |  |  |
| `ai:query` |  |  |  | ❌ |
| `ai:reports` |  |  | ❌ |  |
| `reports:export` |  |  |  |  |
| `rules:manage` |  |  | ❌ | ❌ |
| `users:manage` |  | ❌ | ❌ | ❌ |
| `audit:view` |  | ❌ | ❌ |  |

---

## 4. AI Service Data Sanitization & Safety Guardrails

- **Zero Credential Exposure**: Before transmitting incident descriptions or event metadata to the AI microservice, all payloads undergo strict regex-based redacting of API keys, Bearer tokens, passwords, session cookies, and IPv6/IPv4 private subnet addresses where requested.
- **Human-In-The-Loop**: AI outputs (investigation recommendations, threat classifications) are advisory only. No high-privilege automated actions (such as account locking or IP firewall blocking) execute without human confirmation from a Security Administrator.
- **Fail-Safe & Offline Fallback**: The AI service includes a deterministic rule-based heuristic fallback engine. If an external LLM is offline or unconfigured, the system returns explainable, rule-derived incident summaries and threat recommendations without disruption.

