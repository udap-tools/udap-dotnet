using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace UdapEd.Server.Extensions;

public static class RateLimitExtensions
{
    public const string GetPolicy = "get";
    public  const string Policy = "PerThing";

    public static IServiceCollection AddRateLimiting(this WebApplicationBuilder builder)
    {
        var rateLimitOptions = new RateLimitOptions();
        builder.Configuration.GetSection("RateLimitOptions").Bind(rateLimitOptions);

        return builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.AddConcurrencyLimiter(policyName: GetPolicy, options =>
            {
                options.PermitLimit = rateLimitOptions.PermitLimit;
                options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                options.QueueLimit = rateLimitOptions.QueueLimit;
            });

            options.AddPolicy(Policy, context =>
            {
                IPAddress? remoteIpAddress = context.Connection.RemoteIpAddress;

                if (remoteIpAddress != null && 
                    !IPAddress.IsLoopback(remoteIpAddress))
                {
                    return RateLimitPartition.GetTokenBucketLimiter
                    (remoteIpAddress!, _ =>
                        new TokenBucketRateLimiterOptions
                        {
                            TokenLimit = rateLimitOptions.TokenLimit2,
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = rateLimitOptions.QueueLimit,
                            ReplenishmentPeriod = TimeSpan.FromSeconds(rateLimitOptions.ReplenishmentPeriod),
                            TokensPerPeriod = rateLimitOptions.TokensPerPeriod,
                            AutoReplenishment = rateLimitOptions.AutoReplenishment
                        });
                }

                return RateLimitPartition.GetNoLimiter(IPAddress.Loopback);
            });

            var pages = new[] { "udapBusinessToBusiness", "udapDiscovery", "udapRegistration" };

            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, IPAddress>(context =>
            {
                IPAddress? remoteIpAddress = context.Connection.RemoteIpAddress;
            
                if (remoteIpAddress != null && 
                    !IPAddress.IsLoopback(remoteIpAddress) &&
                    pages.Any(p => string.IsNullOrEmpty(context.Request.QueryString.Value) || 
                                   context.Request.QueryString.Value.StartsWith(p))
                   )
                {
                    return RateLimitPartition.GetTokenBucketLimiter
                    (remoteIpAddress!, _ =>
                        new TokenBucketRateLimiterOptions
                        {
                            TokenLimit = rateLimitOptions.TokenLimit2,
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = rateLimitOptions.QueueLimit,
                            ReplenishmentPeriod = TimeSpan.FromSeconds(rateLimitOptions.ReplenishmentPeriod),
                            TokensPerPeriod = rateLimitOptions.TokensPerPeriod,
                            AutoReplenishment = rateLimitOptions.AutoReplenishment
                        });
                }
            
                return RateLimitPartition.GetNoLimiter(IPAddress.Loopback);
            });
        });
    }
}

public class RateLimitOptions
{
    public const string RateLimit = "RateLimit";
    public int PermitLimit { get; set; } = 40;
    public int Window { get; set; } = 10;
    public int ReplenishmentPeriod { get; set; } = 3;
    public int QueueLimit { get; set; } = 10;
    public int SegmentsPerWindow { get; set; } = 8;
    public int TokenLimit { get; set; } = 10;
    public int TokenLimit2 { get; set; } = 60;
    public int TokensPerPeriod { get; set; } = 10;
    public bool AutoReplenishment { get; set; } = true;
}


