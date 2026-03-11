using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Domain.Entities;

namespace SecureWatch.Application.Interfaces;

public interface IAuthService
{
    Task<ApiResponse<LoginResponseDto>> LoginAsync(LoginRequestDto request, string ipAddress, CancellationToken ct = default);
    Task<ApiResponse<UserProfileDto>> RegisterAsync(RegisterRequestDto request, CancellationToken ct = default);
    Task<ApiResponse<LoginResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto request, string ipAddress, CancellationToken ct = default);
    Task<ApiResponse<bool>> LogoutAsync(string userId, CancellationToken ct = default);
    Task<ApiResponse<UserProfileDto>> GetCurrentUserProfileAsync(string userId, CancellationToken ct = default);
    Task<ApiResponse<bool>> ChangePasswordAsync(string userId, ChangePasswordDto request, CancellationToken ct = default);
}

public interface ISecurityEventService
{
    Task<ApiResponse<SecurityEventDto>> IngestEventAsync(CreateSecurityEventDto request, CancellationToken ct = default);
    Task<ApiResponse<List<SecurityEventDto>>> IngestBatchAsync(List<CreateSecurityEventDto> requests, CancellationToken ct = default);
    Task<ApiResponse<PagedResult<SecurityEventDto>>> GetEventsAsync(EventQueryParameters parameters, CancellationToken ct = default);
    Task<ApiResponse<SecurityEventDto>> GetEventByIdAsync(Guid id, CancellationToken ct = default);
    Task<ApiResponse<EventStatisticsDto>> GetStatisticsAsync(CancellationToken ct = default);
}

public interface IThreatDetectionEngine
{
    Task<List<ThreatDetection>> EvaluateEventAsync(SecurityEvent securityEvent, CancellationToken ct = default);
    Task<ApiResponse<PagedResult<ThreatDetectionDto>>> GetThreatsAsync(ThreatQueryParameters parameters, CancellationToken ct = default);
    Task<ApiResponse<ThreatDetectionDto>> GetThreatByIdAsync(Guid id, CancellationToken ct = default);
    Task<ApiResponse<ThreatStatisticsDto>> GetThreatStatisticsAsync(CancellationToken ct = default);
}

public interface IIncidentService
{
    Task<ApiResponse<PagedResult<IncidentDto>>> GetIncidentsAsync(IncidentQueryParameters parameters, CancellationToken ct = default);
    Task<ApiResponse<IncidentDto>> GetIncidentByIdAsync(Guid id, CancellationToken ct = default);
    Task<ApiResponse<IncidentDto>> CreateIncidentAsync(CreateIncidentDto request, CancellationToken ct = default);
    Task<ApiResponse<IncidentDto>> UpdateIncidentAsync(Guid id, UpdateIncidentDto request, CancellationToken ct = default);
    Task<ApiResponse<IncidentDto>> AssignAnalystAsync(Guid id, string analystId, CancellationToken ct = default);
    Task<ApiResponse<IncidentNoteDto>> AddNoteAsync(Guid id, AddIncidentNoteDto request, string authorId, string authorName, CancellationToken ct = default);
    Task<ApiResponse<IncidentDto>> ResolveIncidentAsync(Guid id, ResolveIncidentDto request, CancellationToken ct = default);
}

public interface IIpReputationService
{
    Task<ApiResponse<IpReputationDto>> GetReputationAsync(string ipAddress, CancellationToken ct = default);
    Task<ApiResponse<IpReputationDto>> ForceRefreshAsync(string ipAddress, CancellationToken ct = default);
    Task RecordIpActivityAsync(string ipAddress, bool isSuspicious, CancellationToken ct = default);
}

public interface IAiAssistantService
{
    Task<ApiResponse<AiIncidentAnalysisResponseDto>> AnalyzeIncidentAsync(AiIncidentAnalysisRequestDto request, CancellationToken ct = default);
    Task<ApiResponse<AiReportResponseDto>> GenerateReportAsync(AiReportRequestDto request, CancellationToken ct = default);
    Task<ApiResponse<AiChatResponseDto>> ChatAsync(AiChatRequestDto request, CancellationToken ct = default);
    Task<ApiResponse<AnomalyDetectionResultDto>> DetectAnomaliesAsync(CancellationToken ct = default);
}

public interface ISecurityHubService
{
    Task BroadcastSecurityEventAsync(SecurityEventDto securityEvent);
    Task BroadcastThreatDetectionAsync(ThreatDetectionDto threat);
    Task BroadcastIncidentCreatedAsync(IncidentDto incident);
    Task BroadcastIncidentUpdatedAsync(IncidentDto incident);
    Task BroadcastAlertAsync(string title, string message, string severity);
}

public interface IAuditLogService
{
    Task LogAsync(string? userId, string username, string action, string entityName, string? entityId, string? ipAddress, object? oldValues = null, object? newValues = null, CancellationToken ct = default);
    Task<ApiResponse<PagedResult<AuditLogDto>>> GetAuditLogsAsync(int pageIndex, int pageSize, string? username = null, string? action = null, CancellationToken ct = default);
}

public interface IDashboardService
{
    Task<ApiResponse<DashboardOverviewDto>> GetOverviewAsync(CancellationToken ct = default);
    Task<ApiResponse<List<ThreatTrendDto>>> GetThreatTrendsAsync(int hours = 24, CancellationToken ct = default);
    Task<ApiResponse<RiskDistributionDto>> GetRiskDistributionAsync(CancellationToken ct = default);
}

public interface IEventSimulatorService
{
    Task<ApiResponse<string>> TriggerScenarioAsync(string scenarioType, CancellationToken ct = default);
    Task<ApiResponse<bool>> ResetDemoDataAsync(CancellationToken ct = default);
}

public interface IAdminService
{
    Task<ApiResponse<List<UserDto>>> GetUsersAsync(CancellationToken ct = default);
    Task<ApiResponse<UserDto>> CreateUserAsync(CreateUserDto request, CancellationToken ct = default);
    Task<ApiResponse<bool>> UpdateUserStatusAsync(string userId, UpdateUserStatusDto request, CancellationToken ct = default);
    Task<ApiResponse<bool>> UpdateUserRoleAsync(string userId, UpdateUserRolesDto request, CancellationToken ct = default);
    Task<ApiResponse<List<RoleDto>>> GetRolesAsync(CancellationToken ct = default);
    Task<ApiResponse<List<SecurityRuleDto>>> GetRulesAsync(CancellationToken ct = default);
    Task<ApiResponse<SecurityRuleDto>> UpdateRuleAsync(Guid id, UpdateSecurityRuleDto request, CancellationToken ct = default);
}

