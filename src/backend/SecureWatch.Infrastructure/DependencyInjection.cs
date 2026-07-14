using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SecureWatch.Application.Common;
using SecureWatch.Application.Interfaces;
using SecureWatch.Infrastructure.Identity;
using SecureWatch.Infrastructure.Persistence;
using SecureWatch.Infrastructure.Services;
using StackExchange.Redis;

namespace SecureWatch.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // 1. Database Configuration (PostgreSQL with In-Memory fallback for environments without running Postgres)
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        var useInMemory = configuration.GetValue<bool>("UseInMemoryDatabase", false) || string.IsNullOrEmpty(connectionString);

        if (useInMemory)
        {
            services.AddDbContext<SecureWatchDbContext>(options =>
                options.UseInMemoryDatabase("SecureWatchDb"));
        }
        else
        {
            services.AddDbContext<SecureWatchDbContext>(options =>
                options.UseNpgsql(connectionString, b => b.MigrationsAssembly(typeof(SecureWatchDbContext).Assembly.FullName)));
        }

        services.AddScoped<ISecurityDbContext>(provider => provider.GetRequiredService<SecureWatchDbContext>());
        services.AddScoped<DatabaseSeeder>();

        // 2. ASP.NET Core Identity
        services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
        {
            // Enterprise Password Policy
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequiredLength = 8;

            // Account Lockout Policy
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;

            // User Settings
            options.User.RequireUniqueEmail = true;
        })
        .AddEntityFrameworkStores<SecureWatchDbContext>()
        .AddDefaultTokenProviders();

        // 3. JWT Authentication & Bearer Token Validation
        var secret = configuration["Jwt:SecretKey"] ?? "SecureWatch_Super_Secret_Key_At_Least_64_Bytes_Long_For_HmacSha512_Compliance_2026";
        var issuer = configuration["Jwt:Issuer"] ?? "SecureWatch";
        var audience = configuration["Jwt:Audience"] ?? "SecureWatchClient";

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = false;
            options.SaveToken = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            };

            // Allow SignalR access token passing via query string (?access_token=...)
            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = context =>
                {
                    var accessToken = context.Request.Query["access_token"];
                    var path = context.HttpContext.Request.Path;
                    if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs"))
                    {
                        context.Token = accessToken;
                    }
                    return Task.CompletedTask;
                }
            };
        });

        // 4. Caching & Redis (with resilient fallback to in-memory)
        services.AddMemoryCache();
        var redisConn = configuration.GetConnectionString("Redis");
        if (!string.IsNullOrEmpty(redisConn))
        {
            try
            {
                var redis = ConnectionMultiplexer.Connect(redisConn);
                services.AddSingleton<IConnectionMultiplexer>(redis);
            }
            catch
            {
                // Fall back gracefully if Redis server is offline
            }
        }
        services.AddSingleton<ICacheService, CacheService>();

        // 5. Context & Identity Services
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUserService, CurrentUserService>();
        services.AddSingleton<IDateTimeProvider, DateTimeProvider>();
        services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();

        // 6. Application Business Services
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAuditLogService, AuditLogService>();
        services.AddScoped<IIpReputationService, IpReputationService>();
        services.AddScoped<IThreatDetectionEngine, ThreatDetectionEngine>();
        services.AddScoped<ISecurityEventService, SecurityEventService>();
        services.AddScoped<IIncidentService, IncidentService>();
        services.AddScoped<IDashboardService, DashboardService>();
        services.AddScoped<IAdminService, AdminService>();
        services.AddScoped<IEventSimulatorService, EventSimulatorService>();

        // 7. SignalR Hub Service
        services.AddSignalR();
        services.AddScoped<ISecurityHubService, SecurityHubService>();

        // 8. Python AI Microservice Client
        services.AddHttpClient<IAiAssistantService, AiAssistantService>();

        return services;
    }
}

