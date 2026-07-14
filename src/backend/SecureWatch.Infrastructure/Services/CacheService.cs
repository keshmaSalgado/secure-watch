using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using SecureWatch.Application.Common;
using StackExchange.Redis;

namespace SecureWatch.Infrastructure.Services;

public class CacheService : ICacheService
{
    private readonly IConnectionMultiplexer? _redis;
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<CacheService> _logger;

    public CacheService(
        IMemoryCache memoryCache,
        ILogger<CacheService> logger,
        IConnectionMultiplexer? redis = null)
    {
        _memoryCache = memoryCache;
        _logger = logger;
        _redis = redis;
    }

    public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            if (_redis != null && _redis.IsConnected)
            {
                var db = _redis.GetDatabase();
                var value = await db.StringGetAsync(key);
                if (value.HasValue)
                {
                    return JsonSerializer.Deserialize<T>(value.ToString()!);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis lookup failed for key '{Key}'. Falling back to in-memory cache.", key);
        }

        return _memoryCache.TryGetValue(key, out T? localValue) ? localValue : default;
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken cancellationToken = default)
    {
        var expiry = expiration ?? TimeSpan.FromMinutes(10);

        try
        {
            if (_redis != null && _redis.IsConnected)
            {
                var db = _redis.GetDatabase();
                var json = JsonSerializer.Serialize(value);
                await db.StringSetAsync(key, json, expiry);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis set failed for key '{Key}'. Falling back to in-memory cache.", key);
        }

        _memoryCache.Set(key, value, expiry);
    }

    public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            if (_redis != null && _redis.IsConnected)
            {
                var db = _redis.GetDatabase();
                await db.KeyDeleteAsync(key);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis delete failed for key '{Key}'.", key);
        }

        _memoryCache.Remove(key);
    }

    public async Task<long> IncrementAsync(string key, TimeSpan? expiration = null, CancellationToken cancellationToken = default)
    {
        try
        {
            if (_redis != null && _redis.IsConnected)
            {
                var db = _redis.GetDatabase();
                var val = await db.StringIncrementAsync(key);
                if (val == 1 && expiration.HasValue)
                {
                    await db.KeyExpireAsync(key, expiration.Value);
                }
                return val;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis increment failed for key '{Key}'. Using in-memory counter.", key);
        }

        // Memory cache fallback counter
        var current = _memoryCache.GetOrCreate(key, entry =>
        {
            if (expiration.HasValue) entry.AbsoluteExpirationRelativeToNow = expiration;
            return 0L;
        });

        current++;
        _memoryCache.Set(key, current, expiration ?? TimeSpan.FromMinutes(10));
        return current;
    }
}

