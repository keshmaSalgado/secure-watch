namespace SecureWatch.Domain.Enums;

public enum ThreatType
{
    BruteForce = 1,
    RapidFailures = 2,
    SuccessAfterFailures = 3,
    MultiAccountTargeting = 4,
    MaliciousIpActivity = 5,
    UnusualLoginTime = 6,
    UnfamiliarLocation = 7,
    PrivilegeEscalationAnomaly = 8,
    MachineLearningAnomaly = 9
}

