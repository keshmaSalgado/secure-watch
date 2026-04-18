namespace SecureWatch.Infrastructure.Identity;

public static class RolePermissions
{
    // Roles
    public const string SuperAdmin = "SuperAdmin";
    public const string SecurityAdmin = "SecurityAdmin";
    public const string SecurityAnalyst = "SecurityAnalyst";
    public const string Auditor = "Auditor";

    // Permission identifiers
    public const string DashboardView = "Permissions.Dashboard.View";
    public const string EventsView = "Permissions.Events.View";
    public const string EventsIngest = "Permissions.Events.Ingest";
    public const string ThreatsView = "Permissions.Threats.View";
    public const string IncidentsView = "Permissions.Incidents.View";
    public const string IncidentsCreate = "Permissions.Incidents.Create";
    public const string IncidentsAssign = "Permissions.Incidents.Assign";
    public const string IncidentsUpdate = "Permissions.Incidents.Update";
    public const string IncidentsResolve = "Permissions.Incidents.Resolve";
    public const string IntelligenceQuery = "Permissions.Intelligence.Query";
    public const string AiQuery = "Permissions.Ai.Query";
    public const string AiReports = "Permissions.Ai.Reports";
    public const string ReportsExport = "Permissions.Reports.Export";
    public const string RulesManage = "Permissions.Rules.Manage";
    public const string UsersManage = "Permissions.Users.Manage";
    public const string AuditView = "Permissions.Audit.View";

    public static readonly Dictionary<string, List<string>> DefaultRolePermissions = new()
    {
        [SuperAdmin] = new List<string>
        {
            DashboardView, EventsView, EventsIngest, ThreatsView, IncidentsView,
            IncidentsCreate, IncidentsAssign, IncidentsUpdate, IncidentsResolve,
            IntelligenceQuery, AiQuery, AiReports, ReportsExport, RulesManage,
            UsersManage, AuditView
        },
        [SecurityAdmin] = new List<string>
        {
            DashboardView, EventsView, EventsIngest, ThreatsView, IncidentsView,
            IncidentsCreate, IncidentsAssign, IncidentsUpdate, IncidentsResolve,
            IntelligenceQuery, AiQuery, AiReports, ReportsExport, RulesManage
        },
        [SecurityAnalyst] = new List<string>
        {
            DashboardView, EventsView, ThreatsView, IncidentsView,
            IncidentsCreate, IncidentsUpdate, IncidentsResolve,
            IntelligenceQuery, AiQuery, ReportsExport
        },
        [Auditor] = new List<string>
        {
            DashboardView, EventsView, ThreatsView, IncidentsView,
            IntelligenceQuery, AiReports, ReportsExport, AuditView
        }
    };
}

