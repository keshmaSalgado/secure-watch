# SecureWatch – REST API Specification (OpenAPI / v1)

All endpoints follow RESTful conventions, returning standard JSON payloads with consistent envelope structures, pagination, and error reporting (`RFC 7807 ProblemDetails`).

Base URL: `/api/v1`

---

## 1. Authentication & Identity (`/api/v1/auth`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `POST` | `/auth/login` | Authenticate user, issue JWT & Refresh Token | Anonymous |
| `POST` | `/auth/register` | Register initial or demo user account | Anonymous |
| `POST` | `/auth/refresh` | Rotate expired JWT using valid Refresh Token | Anonymous |
| `POST` | `/auth/logout` | Revoke active refresh token and end session | Authenticated |
| `GET` | `/auth/me` | Fetch authenticated user profile & permissions | Authenticated |
| `POST` | `/auth/change-password` | Update account password | Authenticated |

---

## 2. Dashboard & Analytics (`/api/v1/dashboard`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `GET` | `/dashboard/overview` | Aggregated metric counters (Total Events, Active Threats, Critical Incidents, Failed Logins) | All Roles |
| `GET` | `/dashboard/threat-trends` | Time-bucketed threat & event volume for charts | All Roles |
| `GET` | `/dashboard/recent-events` | Top 10 most recent ingested security events | All Roles |
| `GET` | `/dashboard/risk-distribution` | Breakdown of events & detections by severity / risk tier | All Roles |

---

## 3. Security Events (`/api/v1/events`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `POST` | `/events` | Ingest single security event (runs through detection engine) | SuperAdmin, SecurityAdmin, Agent |
| `POST` | `/events/batch` | Bulk event ingestion | SuperAdmin, SecurityAdmin, Agent |
| `GET` | `/events` | Paginated search, filter by category, severity, IP, date | All Roles |
| `GET` | `/events/{id}` | Detailed event inspection including JSONB metadata | All Roles |
| `GET` | `/events/statistics` | Breakdown by event type, hourly rate, top source IPs | All Roles |

---

## 4. Threat Detection Engine (`/api/v1/threats`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `GET` | `/threats` | List detected threats with risk scores & trigger reasons | All Roles |
| `GET` | `/threats/{id}` | Detailed threat evidence, related event IDs, and suggestions | All Roles |
| `GET` | `/threats/statistics` | Statistics on triggered rules, average risk score | All Roles |

---

## 5. Incidents Management (`/api/v1/incidents`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `GET` | `/incidents` | Filterable, paginated incident queue | All Roles |
| `POST` | `/incidents` | Manually raise a security incident | SuperAdmin, SecurityAdmin, Analyst |
| `GET` | `/incidents/{id}` | Full incident workspace (timeline, linked events, notes) | All Roles |
| `PUT` | `/incidents/{id}` | Update incident severity, title, or status | SuperAdmin, SecurityAdmin, Analyst |
| `POST` | `/incidents/{id}/assign` | Assign incident to an analyst | SuperAdmin, SecurityAdmin |
| `POST` | `/incidents/{id}/notes` | Add investigation note | SuperAdmin, SecurityAdmin, Analyst |
| `POST` | `/incidents/{id}/resolve` | Conclude incident with root cause analysis & resolution summary | SuperAdmin, SecurityAdmin, Analyst |

---

## 6. Threat Intelligence & IP Reputation (`/api/v1/intelligence`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `GET` | `/intelligence/ip/{address}` | Query reputation score, ASN, ISP, country, proxy/Tor flags, and history | All Roles |
| `POST` | `/intelligence/ip/{address}/refresh` | Force threat intel feed refresh | SuperAdmin, SecurityAdmin |

---

## 7. AI Assistant & ML Engine (`/api/v1/ai`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `POST` | `/ai/analyze-incident` | Send incident details to Python AI microservice for LLM synthesis | SuperAdmin, SecurityAdmin, Analyst |
| `POST` | `/ai/generate-report` | Generate daily/weekly executive summary and threat posture | SuperAdmin, SecurityAdmin, Auditor |
| `POST` | `/ai/chat` | Natural language security Q&A scoped to platform data | SuperAdmin, SecurityAdmin, Analyst |
| `POST` | `/ai/anomaly-detection` | Trigger unsupervised Isolation Forest anomaly scoring on recent events | SuperAdmin, SecurityAdmin |

---

## 8. Simulator & Demo (`/api/v1/simulator`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `POST` | `/simulator/trigger-scenario` | Execute synthetic attack scenario (Brute force, Malicious IP, Credential stuffing) | SuperAdmin, SecurityAdmin |
| `POST` | `/simulator/reset-demo-data` | Re-seed clean synthetic baseline demo dataset | SuperAdmin |

---

## 9. Administration & Audit (`/api/v1/admin`)

| Method | Endpoint | Description | Roles |
|---|---|---|---|
| `GET` | `/admin/users` | List users, status, roles | SuperAdmin |
| `POST` | `/admin/users` | Create new user account | SuperAdmin |
| `PUT` | `/admin/users/{id}/status` | Activate / Deactivate user account | SuperAdmin |
| `PUT` | `/admin/users/{id}/roles` | Assign roles to user | SuperAdmin |
| `GET` | `/admin/roles` | List roles and assigned permissions | SuperAdmin |
| `GET` | `/admin/rules` | List security detection rules | SuperAdmin, SecurityAdmin |
| `PUT` | `/admin/rules/{id}` | Update rule threshold, window, or toggle enabled | SuperAdmin, SecurityAdmin |
| `GET` | `/admin/audit-logs` | Immutable audit trail query with date and user filter | SuperAdmin, Auditor |

