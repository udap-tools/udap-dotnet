#if NET7_0

using System.Net;
using System.Threading.RateLimiting;
using FhirLabsApi.Models;
using Microsoft.AspNetCore.RateLimiting;

namespace FhirLabsApi.Extensions;

public static class RateLimitExtensions
{
    public static readonly string GetPolicy = "get";
    public static readonly string Policy = "PerUserRatelimit";

    public static IServiceCollection AddRateLimiting(this WebApplicationBuilder builder)
    {
        var rateLimitOptions = new RateLimitOptions();
        builder.Configuration.GetSection("RateLimitOptions").Bind(rateLimitOptions);

        return builder.Services.AddRateLimiter(limiterOptions =>
        {
            limiterOptions.OnRejected = (context, cancellationToken) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                return new ValueTask();
            };

            limiterOptions.AddConcurrencyLimiter(policyName: GetPolicy, options =>
            {
                options.PermitLimit = rateLimitOptions.PermitLimit;
                options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                options.QueueLimit = rateLimitOptions.QueueLimit;
            });

            limiterOptions.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, IPAddress>(context =>
            {
                IPAddress? remoteIpAddress = context.Connection.RemoteIpAddress;

                if (remoteIpAddress != null &&  // Unit tests do not have a RemoteIpAddress
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
        });
    }
}


#endif


