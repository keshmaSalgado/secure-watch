namespace SecureWatch.Domain.Enums;

public enum EventCategory
{
    SuccessfulLogin = 1,
    FailedLogin = 2,
    PasswordChange = 3,
    UnauthorizedAccess = 4,
    SuspiciousApiRequest = 5,
    AccountLockout = 6,
    PrivilegeEscalation = 7,
    AdministrativeAction = 8,
    ServerSecurityEvent = 9
}

