using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureWatch.Infrastructure.Identity;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Tests;

public static class TestDbContextFactory
{
    public static SecureWatchDbContext CreateInMemoryDbContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<SecureWatchDbContext>()
            .UseInMemoryDatabase(databaseName: dbName)
            .Options;

        var context = new SecureWatchDbContext(options);
        return context;
    }
}

