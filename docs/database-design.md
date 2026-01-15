# SecureWatch – Database Design & Schema Specification

## 1. Overview
SecureWatch uses **PostgreSQL 16+** with **Entity Framework Core (Npgsql)**. The schema balances normalized relational tables for transactional integrity (users, roles, permissions, incidents, detections, audit trails) with high-efficiency indexing and JSONB storage for polymorphic event metadata.

All timestamps are stored in UTC (`timestamp with time zone`). Soft deletion (`is_deleted`, `deleted_at`) is applied to critical entities such as users, rules, and incidents to prevent accidental data loss.

---

## 2. Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    ApplicationUser ||--o{ UserRole : has
    ApplicationRole ||--o{ UserRole : assigned_to
    ApplicationRole ||--o{ RolePermission : contains
    ApplicationUser ||--o{ RefreshToken : owns
    ApplicationUser ||--o{ UserSession : logs

    ApplicationUser ||--o{ Incident : assigns
    ApplicationUser ||--o{ IncidentNote : writes
    
    SecurityRule ||--o{ ThreatDetection : generates
    ThreatDetection ||--o{ Incident : triggers
    
    Incident ||--o{ IncidentEvent : links
    SecurityEvent ||--o{ IncidentEvent : linked_to
    
    Incident ||--o{ IncidentNote : has
    Incident ||--o{ Alert : creates
    
    IPReputation ||--o{ SecurityEvent : enriches
    ApplicationUser ||--o{ AuditLog : performs

    ApplicationUser {
        uuid id PK
        string email
        string password_hash
        string first_name
        string last_name
        string department
        bool is_active
        bool is_deleted
        timestamp created_at
        timestamp updated_at
    }

    ApplicationRole {
        uuid id PK
        string name
        string description
        bool is_system_role
    }

    RolePermission {
        uuid id PK
        uuid role_id FK
        string permission
    }

    RefreshToken {
        uuid id PK
        uuid user_id FK
        string token_hash
        string created_by_ip
        timestamp expires_at
        timestamp created_at
        timestamp revoked_at
        string replaced_by_token
        bool is_revoked
    }

    SecurityEvent {
        uuid id PK
        string event_type
        int category
        int severity
        string source_ip
        string destination_ip
        string user_id_ref
        string username
        timestamp event_timestamp
        string device_info
        string user_agent
        string description
        string processing_status
        jsonb metadata
        timestamp created_at
    }

    SecurityRule {
        uuid id PK
        string name
        string code
        string description
        int category
        int severity
        int time_window_seconds
        int threshold_count
        bool is_enabled
        string condition_expression
        jsonb parameters
        timestamp created_at
        timestamp updated_at
    }

    ThreatDetection {
        uuid id PK
        uuid rule_id FK
        string rule_name
        string detection_reason
        int severity
        int risk_score
        string source_ip
        string targeted_username
        timestamp detected_at
        jsonb evidence_event_ids
        string recommended_actions
        bool incident_created
        uuid incident_id FK
    }

    Incident {
        uuid id PK
        string incident_code
        string title
        string description
        int severity
        int risk_score
        int status
        uuid assigned_analyst_id FK
        string source_ip
        timestamp created_at
        timestamp updated_at
        timestamp resolved_at
        string resolution_summary
        bool is_deleted
    }

    IncidentEvent {
        uuid id PK
        uuid incident_id FK
        uuid security_event_id FK
        timestamp linked_at
    }

    IncidentNote {
        uuid id PK
        uuid incident_id FK
        uuid author_id FK
        string author_name
        string note_text
        bool is_internal_only
        timestamp created_at
        timestamp updated_at
    }

    IPReputation {
        string ip_address PK
        int reputation_score
        bool is_malicious
        bool is_tor
        bool is_vpn_or_proxy
        string country_code
        string country_name
        string region
        string city
        string isp
        string asn
        int total_events_recorded
        timestamp last_checked_at
        timestamp created_at
    }

    Alert {
        uuid id PK
        uuid incident_id FK
        string title
        string message
        int severity
        bool is_acknowledged
        uuid acknowledged_by_id FK
        timestamp acknowledged_at
        timestamp created_at
    }

    AuditLog {
        uuid id PK
        uuid user_id FK
        string username
        string action
        string entity_name
        string entity_id
        string ip_address
        string user_agent
        jsonb old_values
        jsonb new_values
        timestamp timestamp
    }
```

---

## 3. Table Specifications & Indexing Strategy

### 3.1 `security_events`
- **Primary Key**: `id` (UUID v7 / Sequential GUID)
- **Indexes**:
  - `idx_events_timestamp` on `event_timestamp DESC` (Critical for time-series queries & sliding window detection)
  - `idx_events_source_ip_timestamp` on `(source_ip, event_timestamp DESC)` (Critical for IP correlation & brute force rules)
  - `idx_events_user_timestamp` on `(user_id_ref, event_timestamp DESC)` (Critical for user behavior anomalies)
  - `idx_events_category_severity` on `(category, severity)` (Dashboard filtering)
  - GIN Index `idx_events_metadata_gin` on `metadata` (Fast JSON queries)

### 3.2 `incidents`
- **Primary Key**: `id` (UUID)
- **Unique**: `incident_code` (e.g. `SEC-2026-0001`)
- **Indexes**:
  - `idx_incidents_status_severity` on `(status, severity)`
  - `idx_incidents_assigned_analyst` on `assigned_analyst_id`
  - `idx_incidents_created_at` on `created_at DESC`

### 3.3 `threat_detections`
- **Primary Key**: `id` (UUID)
- **Indexes**:
  - `idx_threats_detected_at` on `detected_at DESC`
  - `idx_threats_source_ip` on `source_ip`
  - `idx_threats_rule_id` on `rule_id`

### 3.4 `ip_reputations`
- **Primary Key**: `ip_address` (VARCHAR(45) supporting IPv4 and IPv6)
- **Indexes**:
  - `idx_ip_rep_score` on `reputation_score`
  - `idx_ip_is_malicious` on `is_malicious`

### 3.5 `audit_logs`
- **Primary Key**: `id` (UUID)
- **Append-Only**: Immutability enforced through API policies. No update/delete endpoints provided.
- **Indexes**:
  - `idx_audit_timestamp` on `timestamp DESC`
  - `idx_audit_user_action` on `(user_id, action)`

