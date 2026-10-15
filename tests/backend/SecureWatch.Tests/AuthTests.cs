using FluentAssertions;
using Microsoft.Extensions.Configuration;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Validators;
using SecureWatch.Domain.Entities;
using SecureWatch.Infrastructure.Identity;
using Xunit;

namespace SecureWatch.Tests;

public class AuthTests
{
    [Fact]
    public void LoginRequestValidator_ShouldFail_WhenEmailIsInvalid()
    {
        var validator = new LoginRequestValidator();
        var result = validator.Validate(new LoginRequestDto
        {
            Email = "invalid-email-address",
            Password = "Password123!"
        });

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Email");
    }

    [Fact]
    public void RegisterRequestValidator_ShouldFail_WhenPasswordDoesNotMeetComplexity()
    {
        var validator = new RegisterRequestValidator();
        var result = validator.Validate(new RegisterRequestDto
        {
            Email = "test@securewatch.local",
            FirstName = "Test",
            LastName = "User",
            Password = "alllowercasepassword" // missing uppercase & digit
        });

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Password");
    }

    [Fact]
    public void JwtTokenGenerator_ShouldGenerateValidTokens()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SecretKey"] = "SuperSecretKeyForJwtAuthentication_SecureWatch_AtLeast64BytesLong2026!",
                ["Jwt:Issuer"] = "SecureWatch",
                ["Jwt:Audience"] = "SecureWatchClient",
                ["Jwt:ExpiryMinutes"] = "15"
            })
            .Build();

        var generator = new JwtTokenGenerator(config);
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = "secadmin@securewatch.local",
            FirstName = "Sarah",
            LastName = "Connor"
        };

        var permissions = new List<string> { RolePermissions.DashboardView, RolePermissions.IncidentsView };
        var (token, expiresAt) = generator.GenerateAccessToken(user, RolePermissions.SecurityAdmin, permissions);

        token.Should().NotBeNullOrWhiteSpace();
        expiresAt.Should().BeAfter(DateTime.UtcNow);

        var refreshToken = generator.GenerateRefreshToken();
        refreshToken.Should().NotBeNullOrWhiteSpace();
        refreshToken.Length.Should().BeGreaterThan(40);
    }
}

