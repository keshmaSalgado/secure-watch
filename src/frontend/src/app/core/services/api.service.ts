import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  ApiResponse, PagedResult, DashboardOverview, ThreatTrend, RiskDistribution,
  SecurityEvent, ThreatDetection, Incident, IncidentNote, IpReputation,
  AiIncidentAnalysis, AiReport, AiChatResponse, AnomalyDetectionResult,
  UserItem, SecurityRuleItem, AuditLogItem
} from '../models/types';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private readonly baseUrl = 'http://localhost:5000/api/v1';

  constructor(private http: HttpClient) {}

  // Dashboard
  getDashboardOverview(): Observable<ApiResponse<DashboardOverview>> {
    return this.http.get<ApiResponse<DashboardOverview>>(`${this.baseUrl}/dashboard/overview`);
  }

  getThreatTrends(hours: number = 24): Observable<ApiResponse<ThreatTrend[]>> {
    return this.http.get<ApiResponse<ThreatTrend[]>>(`${this.baseUrl}/dashboard/threat-trends?hours=${hours}`);
  }

  getRiskDistribution(): Observable<ApiResponse<RiskDistribution>> {
    return this.http.get<ApiResponse<RiskDistribution>>(`${this.baseUrl}/dashboard/risk-distribution`);
  }

  // Security Events
  getEvents(params?: any): Observable<ApiResponse<PagedResult<SecurityEvent>>> {
    let httpParams = new HttpParams();
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== null && params[key] !== undefined && params[key] !== '') {
          httpParams = httpParams.set(key, params[key]);
        }
      });
    }
    return this.http.get<ApiResponse<PagedResult<SecurityEvent>>>(`${this.baseUrl}/events`, { params: httpParams });
  }

  getEventById(id: string): Observable<ApiResponse<SecurityEvent>> {
    return this.http.get<ApiResponse<SecurityEvent>>(`${this.baseUrl}/events/${id}`);
  }

  // Threats
  getThreats(params?: any): Observable<ApiResponse<PagedResult<ThreatDetection>>> {
    let httpParams = new HttpParams();
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== null && params[key] !== undefined && params[key] !== '') {
          httpParams = httpParams.set(key, params[key]);
        }
      });
    }
    return this.http.get<ApiResponse<PagedResult<ThreatDetection>>>(`${this.baseUrl}/threats`, { params: httpParams });
  }

  // Incidents
  getIncidents(params?: any): Observable<ApiResponse<PagedResult<Incident>>> {
    let httpParams = new HttpParams();
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== null && params[key] !== undefined && params[key] !== '') {
          httpParams = httpParams.set(key, params[key]);
        }
      });
    }
    return this.http.get<ApiResponse<PagedResult<Incident>>>(`${this.baseUrl}/incidents`, { params: httpParams });
  }

  getIncidentById(id: string): Observable<ApiResponse<Incident>> {
    return this.http.get<ApiResponse<Incident>>(`${this.baseUrl}/incidents/${id}`);
  }

  createIncident(data: any): Observable<ApiResponse<Incident>> {
    return this.http.post<ApiResponse<Incident>>(`${this.baseUrl}/incidents`, data);
  }

  assignIncident(id: string, analystId: string): Observable<ApiResponse<Incident>> {
    return this.http.post<ApiResponse<Incident>>(`${this.baseUrl}/incidents/${id}/assign`, JSON.stringify(analystId), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  addIncidentNote(id: string, noteText: string, isInternalOnly: boolean = false): Observable<ApiResponse<IncidentNote>> {
    return this.http.post<ApiResponse<IncidentNote>>(`${this.baseUrl}/incidents/${id}/notes`, { noteText, isInternalOnly });
  }

  resolveIncident(id: string, resolutionSummary: string, rootCause?: string): Observable<ApiResponse<Incident>> {
    return this.http.post<ApiResponse<Incident>>(`${this.baseUrl}/incidents/${id}/resolve`, { resolutionSummary, rootCause });
  }

  // IP Intelligence
  getIpReputation(ip: string): Observable<ApiResponse<IpReputation>> {
    return this.http.get<ApiResponse<IpReputation>>(`${this.baseUrl}/intelligence/ip/${ip}`);
  }

  refreshIpReputation(ip: string): Observable<ApiResponse<IpReputation>> {
    return this.http.post<ApiResponse<IpReputation>>(`${this.baseUrl}/intelligence/ip/${ip}/refresh`, {});
  }

  // AI Assistant
  analyzeIncidentWithAi(incidentId: string): Observable<ApiResponse<AiIncidentAnalysis>> {
    return this.http.post<ApiResponse<AiIncidentAnalysis>>(`${this.baseUrl}/ai/analyze-incident`, { incidentId });
  }

  generateAiReport(reportType: string = 'DailySummary'): Observable<ApiResponse<AiReport>> {
    return this.http.post<ApiResponse<AiReport>>(`${this.baseUrl}/ai/generate-report`, { reportType });
  }

  chatWithAi(query: string, incidentId?: string, ipAddress?: string): Observable<ApiResponse<AiChatResponse>> {
    return this.http.post<ApiResponse<AiChatResponse>>(`${this.baseUrl}/ai/chat`, { query, incidentId, ipAddress });
  }

  detectAnomalies(): Observable<ApiResponse<AnomalyDetectionResult>> {
    return this.http.post<ApiResponse<AnomalyDetectionResult>>(`${this.baseUrl}/ai/anomaly-detection`, {});
  }

  // Admin
  getUsers(): Observable<ApiResponse<UserItem[]>> {
    return this.http.get<ApiResponse<UserItem[]>>(`${this.baseUrl}/admin/users`);
  }

  createUser(data: any): Observable<ApiResponse<UserItem>> {
    return this.http.post<ApiResponse<UserItem>>(`${this.baseUrl}/admin/users`, data);
  }

  updateUserStatus(id: string, isActive: boolean): Observable<ApiResponse<boolean>> {
    return this.http.put<ApiResponse<boolean>>(`${this.baseUrl}/admin/users/${id}/status`, { isActive });
  }

  updateUserRole(id: string, role: string): Observable<ApiResponse<boolean>> {
    return this.http.put<ApiResponse<boolean>>(`${this.baseUrl}/admin/users/${id}/roles`, { role });
  }

  getRules(): Observable<ApiResponse<SecurityRuleItem[]>> {
    return this.http.get<ApiResponse<SecurityRuleItem[]>>(`${this.baseUrl}/admin/rules`);
  }

  updateRule(id: string, data: any): Observable<ApiResponse<SecurityRuleItem>> {
    return this.http.put<ApiResponse<SecurityRuleItem>>(`${this.baseUrl}/admin/rules/${id}`, data);
  }

  getAuditLogs(pageIndex: number = 1, pageSize: number = 20): Observable<ApiResponse<PagedResult<AuditLogItem>>> {
    return this.http.get<ApiResponse<PagedResult<AuditLogItem>>>(`${this.baseUrl}/admin/audit-logs?pageIndex=${pageIndex}&pageSize=${pageSize}`);
  }

  // Simulator
  triggerSimulation(scenarioType: string): Observable<ApiResponse<string>> {
    return this.http.post<ApiResponse<string>>(`${this.baseUrl}/simulator/trigger-scenario?scenarioType=${scenarioType}`, {});
  }

  resetDemoData(): Observable<ApiResponse<boolean>> {
    return this.http.post<ApiResponse<boolean>>(`${this.baseUrl}/simulator/reset-demo-data`, {});
  }
}

