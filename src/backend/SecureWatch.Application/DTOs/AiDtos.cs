namespace SecureWatch.Application.DTOs;

public class AiIncidentAnalysisRequestDto
{
    public Guid IncidentId { get; set; }
}

public class AiIncidentAnalysisResponseDto
{
    public Guid IncidentId { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string AttackCategory { get; set; } = string.Empty;
    public List<string> SuspiciousIndicators { get; set; } = new();
    public string PotentialImpact { get; set; } = string.Empty;
    public List<string> Recommendations { get; set; } = new();
    public string ConfidenceScore { get; set; } = "High";
    public bool IsDeterministicFallback { get; set; }
}

public class AiReportRequestDto
{
    public string ReportType { get; set; } = "DailySummary"; // DailySummary, WeeklyThreats, TrendAnalysis
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
}

public class AiReportResponseDto
{
    public string Title { get; set; } = string.Empty;
    public string ExecutiveSummary { get; set; } = string.Empty;
    public List<string> KeyObservations { get; set; } = new();
    public List<string> CriticalRiskAreas { get; set; } = new();
    public List<string> RecommendedMitigations { get; set; } = new();
    public DateTime GeneratedAtUtc { get; set; }
    public bool IsDeterministicFallback { get; set; }
}

public class AiChatRequestDto
{
    public string Query { get; set; } = string.Empty;
    public Guid? ContextIncidentId { get; set; }
    public string? ContextIpAddress { get; set; }
}

public class AiChatResponseDto
{
    public string Answer { get; set; } = string.Empty;
    public List<string> ReferencedEntities { get; set; } = new();
    public List<string> SuggestedFollowups { get; set; } = new();
    public DateTime TimestampUtc { get; set; }
}

public class AnomalyDetectionResultDto
{
    public int AnalyzedEventsCount { get; set; }
    public int AnomaliesDetectedCount { get; set; }
    public List<AnomalyScoreItemDto> AnomalyItems { get; set; } = new();
    public DateTime AnalyzedAtUtc { get; set; }
}

public class AnomalyScoreItemDto
{
    public Guid EventId { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public string? Username { get; set; }
    public double AnomalyScore { get; set; } // Outlier magnitude
    public string Reason { get; set; } = string.Empty;
}

