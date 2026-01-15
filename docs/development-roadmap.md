# SecureWatch – Development Roadmap & Execution Phases

```
Phase 1: Architecture, Project Structure & Database Design ──────────► [CURRENT]
Phase 2: Backend Clean Architecture Foundation (Domain & Application)
Phase 3: Persistence, ASP.NET Identity, Seeders & JWT/Refresh Tokens
Phase 4: Security Event Ingestion & Threat Detection Engine
Phase 5: Incident Management & Real-Time SignalR Notifications
Phase 6: Python AI Microservice (FastAPI, Isolation Forest, Copilot)
Phase 7: Administration, Audit Logs, IP Reputation & Event Simulator
Phase 8: Angular Frontend (Dark Theme, Real-time Dashboard, Incident Workspace)
Phase 9: Comprehensive Automated Tests (Backend xUnit, Python pytest, Integration)
Phase 10: Docker Compose, Nginx, CI/CD Pipeline & Final Portfolio Polish
```

---

## Detailed Phase Breakdown

### Phase 1: Architecture, Project Structure & Database Design
- [x] Initialized Git repository and environment checks (.NET 10, Node 24, Python 3.14).
- [x] Authored architecture specifications, ERD, API specs, and security design.
- [ ] Scaffold solution and project structure (`src/backend`, `src/frontend`, `src/ai-service`, `tests`).

### Phase 2: Domain Entities & Application Contracts
- [ ] Implement Domain entities (`SecurityEvent`, `Incident`, `ThreatDetection`, `SecurityRule`, `IPReputation`, `AuditLog`, `Alert`).
- [ ] Implement Enums and Value Objects.
- [ ] Implement Application Interfaces, DTOs, and FluentValidation rules.

### Phase 3: Infrastructure, Database & Identity
- [ ] EF Core DbContext with PostgreSQL Npgsql provider (and In-Memory/SQLite fallback for tests).
- [ ] ASP.NET Core Identity integration with JWT access tokens and rotating refresh tokens.
- [ ] Comprehensive database seeder with preconfigured demo accounts, rules, and initial security events.

### Phase 4: Event Ingestion & Threat Detection Engine
- [ ] Event Ingestion API with validation and IP enrichment.
- [ ] Threat Detection Engine with 7 core security detection rules:
  1. 5 failed logins within 1 minute.
  2. 20 failed logins within 2 minutes.
  3. Successful login immediately following repeated failures.
  4. Multiple accounts accessed from one IP address.
  5. Login from a known malicious IP.
  6. Unusual login time compared with baseline.
  7. Multiple login attempts from unfamiliar locations.
- [ ] Explainable Risk Scoring Engine (0–100 scale: Low, Medium, High, Critical).

### Phase 5: Incident Management & SignalR Real-Time Communications
- [ ] Automatic incident creation from High/Critical threats.
- [ ] Incident lifecycle: Open -> Investigating -> Escalated -> Resolved -> Closed.
- [ ] Investigation notes, assignment, and resolution tracking.
- [ ] SignalR Hub (`/hubs/security`) with real-time broadcasting.

### Phase 6: Python AI Microservice (FastAPI)
- [ ] FastAPI service setup with modular routers.
- [ ] Scikit-learn `IsolationForest` unsupervised anomaly detector.
- [ ] LLM provider abstraction with deterministic security fallback.
- [ ] Endpoints: `/ai/analyze-incident`, `/ai/generate-report`, `/ai/chat`, `/ai/anomaly-detection`.

### Phase 7: IP Reputation, Administration, Simulator & Audit
- [ ] IP intelligence provider with GeoIP, ASN, and risk indicators.
- [ ] Simulator engine for generating synthetic attack scenarios.
- [ ] User, role, and security rule management APIs.
- [ ] Immutable audit logging.

### Phase 8: Angular Frontend
- [ ] Modern Angular SPA with Tailwind CSS and dark cybersecurity theme (#0B1120).
- [ ] Authentication: Login, demo user switcher, token refresh interceptor.
- [ ] Dashboard: Metric cards, real-time event ticker, Chart.js/ECharts trends.
- [ ] Modules: Live Monitoring, Security Events, Threat Detection, Incidents, IP Intel, AI Assistant, Admin Panel, Event Simulator.

### Phase 9: Automated Testing
- [ ] Backend xUnit unit and integration tests.
- [ ] Python pytest tests for Isolation Forest and AI fallbacks.
- [ ] Frontend test specifications.

### Phase 10: Containerization, DevOps & Documentation
- [ ] Multi-stage Dockerfiles for Backend, Frontend, and AI Service.
- [ ] `docker-compose.yml` with health checks, Redis, and PostgreSQL.
- [ ] GitHub Actions CI workflow.
- [ ] README.md portfolio documentation.

