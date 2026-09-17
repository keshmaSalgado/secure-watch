export interface ApiResponse<T> {
  success: boolean;
  message?: string;
  data?: T;
  errors?: string[];
}

export interface PagedResult<T> {
  items: T[];
  pageIndex: number;
  pageSize: number;
  totalCount: number;
  totalPages: number;
  hasPreviousPage: boolean;
  hasNextPage: boolean;
}

export interface UserProfile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  fullName: string;
  role: string;
  permissions: string[];
  createdAtUtc: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresAtUtc: string;
  user: UserProfile;
}

export interface DashboardOverview {
  totalEvents: number;
  totalThreatsDetected: number;
  criticalIncidents: number;
  activeIncidents: number;
  failedLoginAttempts: number;
  suspiciousIpCount: number;
  overallRiskScore: number;
  overallRiskLevel: string;
  recentEvents: SecurityEvent[];
  recentIncidents: Incident[];
}

export interface ThreatTrend {
  timeLabel: string;
  eventCount: number;
  threatCount: number;
  failedLogins: number;
}

export interface RiskDistribution {
  lowCount: number;
  mediumCount: number;
  highCount: number;
  criticalCount: number;
}

export interface SecurityEvent {
  id: string;
  eventType: string;
  category: number;
  categoryName: string;
  severity: number;
  severityName: string;
  sourceIp: string;
  destinationIp?: string;
  userIdRef?: string;
  username?: string;
  eventTimestampUtc: string;
  deviceInfo?: string;
  userAgent?: string;
  description: string;
  processingStatus: string;
  metadataJson?: string;
  isSimulated: boolean;
  createdAtUtc?: string;
}

export interface ThreatDetection {
  id: string;
  ruleId: string;
  ruleName: string;
  threatType: number;
  threatTypeName: string;
  detectionReason: string;
  severity: number;
  severityName: string;
  riskScore: number;
  riskLevel: string;
  sourceIp: string;
  targetedUsername?: string;
  detectedAtUtc: string;
  evidenceEventIds: string[];
  recommendedActions: string;
  incidentCreated: boolean;
  incidentId?: string;
  isSimulated: boolean;
}

export interface Incident {
  id: string;
  incidentCode: string;
  title: string;
  description: string;
  severity: number;
  severityName: string;
  riskScore: number;
  status: number;
  statusName: string;
  assignedAnalystId?: string;
  assignedAnalystName?: string;
  sourceIp?: string;
  createdAtUtc: string;
  updatedAtUtc?: string;
  resolvedAtUtc?: string;
  resolutionSummary?: string;
  rootCause?: string;
  isSimulated: boolean;
  linkedEventsCount: number;
  notes?: IncidentNote[];
  linkedEvents?: SecurityEvent[];
}

export interface IncidentNote {
  id: string;
  incidentId: string;
  authorId: string;
  authorName: string;
  noteText: string;
  isInternalOnly: boolean;
  createdAtUtc: string;
}

export interface IpReputation {
  ipAddress: string;
  reputationScore: number;
  isMalicious: boolean;
  isTor: boolean;
  isVpnOrProxy: boolean;
  countryCode?: string;
  countryName?: string;
  region?: string;
  city?: string;
  isp?: string;
  asn?: string;
  totalEventsRecorded: number;
  lastCheckedAtUtc: string;
  recentEvents: SecurityEvent[];
  recentThreats: ThreatDetection[];
}

export interface AiIncidentAnalysis {
  incidentId: string;
  summary: string;
  attackCategory: string;
  suspiciousIndicators: string[];
  potentialImpact: string;
  recommendations: string[];
  confidenceScore: string;
  isDeterministicFallback: boolean;
}

export interface AiReport {
  title: string;
  executiveSummary: string;
  keyObservations: string[];
  criticalRiskAreas: string[];
  recommendedMitigations: string[];
  generatedAtUtc: string;
  isDeterministicFallback: boolean;
}

export interface AiChatResponse {
  answer: string;
  referencedEntities: string[];
  suggestedFollowups: string[];
  timestampUtc: string;
}

export interface AnomalyDetectionResult {
  analyzedEventsCount: number;
  anomaliesDetectedCount: number;
  anomalyItems: AnomalyItem[];
  analyzedAtUtc: string;
}

export interface AnomalyItem {
  eventId: string;
  sourceIp: string;
  username?: string;
  anomalyScore: number;
  reason: string;
}

export interface UserItem {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  isActive: boolean;
  createdAtUtc: string;
  lastLoginUtc?: string;
}

export interface SecurityRuleItem {
  id: string;
  name: string;
  code: string;
  description: string;
  category: number;
  threatType: number;
  severity: number;
  timeWindowSeconds: number;
  thresholdCount: number;
  isEnabled: boolean;
  baseRiskScore: number;
}

export interface AuditLogItem {
  id: string;
  userId?: string;
  username: string;
  action: string;
  entityName: string;
  entityId?: string;
  ipAddress?: string;
  oldValuesJson?: string;
  newValuesJson?: string;
  timestampUtc: string;
}

