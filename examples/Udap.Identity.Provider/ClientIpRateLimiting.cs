#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace Udap.Identity.Provider;

/// <summary>
/// Per client IP fixed window rate limiting. Replaces the Cloud Armor throttle rule
/// (500 requests per minute per IP) that sat in front of the Cloud Run service.
/// Bound from the "RateLimiting" configuration section.
/// </summary>
public sealed class ClientIpRateLimitOptions
{
    public const string SectionName = "RateLimiting";

    /// <summary>Turn the limiter on or off.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Requests allowed per client IP per window.</summary>
    public int PermitLimit { get; set; } = 500;

    /// <summary>Window length in seconds.</summary>
    public int WindowSeconds { get; set; } = 60;

    /// <summary>
    /// Header that carries the forwarded-for chain. Google's external Application Load Balancer
    /// appends "CLIENT_IP,LOAD_BALANCER_IP" to X-Forwarded-For. Anything left of CLIENT_IP was
    /// supplied by the caller and must not be trusted.
    /// </summary>
    public string ForwardedForHeader { get; set; } = "X-Forwarded-For";

    /// <summary>
    /// Number of trusted proxy entries at the right end of the forwarded-for chain.
    /// 1 = the Google load balancer IP, so the client is the second entry from the right.
    /// Used when <see cref="LoadBalancerIps"/> is empty or none of them is found in the header.
    /// 0 = use the rightmost entry (direct Cloud Run, no load balancer).
    /// </summary>
    public int TrustedProxyHops { get; set; } = 1;

    /// <summary>
    /// Optional forwarding rule IPs of the load balancer. When set, the client IP is the entry
    /// immediately left of the rightmost matching load balancer IP, which stays correct even if
    /// another proxy appends entries after the load balancer.
    /// </summary>
    public string[] LoadBalancerIps { get; set; } = [];

    /// <summary>Client IPs or CIDR ranges that are never limited.</summary>
    public string[] ExemptIps { get; set; } = [];
}

public static class ClientIpRateLimitingExtensions
{
    public static IServiceCollection AddClientIpRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(ClientIpRateLimitOptions.SectionName).Get<ClientIpRateLimitOptions>()
                      ?? new ClientIpRateLimitOptions();

        services.AddSingleton(options);

        if (!options.Enabled)
        {
            return services;
        }

        var lbIps = ParseAddresses(options.LoadBalancerIps);
        var exempt = options.ExemptIps
            .Select(e => e.Trim())
            .Where(e => e.Length > 0)
            .Select(e => e.Contains('/') ? IPNetwork.Parse(e) : IPNetwork.Parse($"{e}/{(IPAddress.Parse(e).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32)}"))
            .ToArray();
        var window = TimeSpan.FromSeconds(Math.Max(1, options.WindowSeconds));

        services.AddRateLimiter(rl =>
        {
            rl.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            rl.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                var clientIp = ClientIpResolver.Resolve(httpContext, options, lbIps);

                if (clientIp != null && exempt.Any(n => n.Contains(clientIp)))
                {
                    return RateLimitPartition.GetNoLimiter("exempt");
                }

                return RateLimitPartition.GetFixedWindowLimiter(clientIp?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = options.PermitLimit,
                    Window = window,
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
            });
            rl.OnRejected = (context, _) =>
            {
                var http = context.HttpContext;
                http.Response.Headers.RetryAfter = ((int)window.TotalSeconds).ToString();
                var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ClientIpRateLimiting");
                logger.LogWarning("Rate limit exceeded for client {ClientIp} on {Method} {Path}",
                    ClientIpResolver.Resolve(http, options, lbIps), http.Request.Method, http.Request.Path);
                return ValueTask.CompletedTask;
            };
        });

        return services;
    }

    /// <summary>
    /// Add early in the pipeline, before UseForwardedHeaders, which rewrites X-Forwarded-For.
    /// </summary>
    public static IApplicationBuilder UseClientIpRateLimiting(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<ClientIpRateLimitOptions>();
        return options.Enabled ? app.UseRateLimiter() : app;
    }

    internal static IPAddress[] ParseAddresses(IEnumerable<string> values) =>
        values.Select(v => IPAddress.TryParse(v.Trim(), out var ip) ? ip : null)
            .Where(ip => ip != null)
            .Select(ip => ip!.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip)
            .ToArray();
}

public static class ClientIpResolver
{
    public static IPAddress? Resolve(HttpContext httpContext, ClientIpRateLimitOptions options, IReadOnlyCollection<IPAddress> loadBalancerIps)
    {
        var forwarded = httpContext.Request.Headers[options.ForwardedForHeader];
        var fromHeader = FromForwardedFor(forwarded.ToArray(), options.TrustedProxyHops, loadBalancerIps);
        if (fromHeader != null)
        {
            return fromHeader;
        }

        var remote = httpContext.Connection.RemoteIpAddress;
        return remote is { IsIPv4MappedToIPv6: true } ? remote.MapToIPv4() : remote;
    }

    /// <summary>
    /// Picks the client entry from a forwarded-for chain, reading from the right.
    /// </summary>
    public static IPAddress? FromForwardedFor(string?[] headerValues, int trustedProxyHops, IReadOnlyCollection<IPAddress> loadBalancerIps)
    {
        var entries = headerValues
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .SelectMany(v => v!.Split(','))
            .Select(e => e.Trim())
            .ToList();

        if (entries.Count == 0)
        {
            return null;
        }

        if (loadBalancerIps.Count > 0)
        {
            for (var i = entries.Count - 1; i > 0; i--)
            {
                var candidate = ParseEntry(entries[i]);
                if (candidate != null && loadBalancerIps.Contains(candidate))
                {
                    return ParseEntry(entries[i - 1]);
                }
            }
        }

        var index = entries.Count - 1 - Math.Max(0, trustedProxyHops);
        // Fewer entries than trusted hops: only the platform appended an entry, so the
        // leftmost (and only trustworthy) entry is the caller.
        return ParseEntry(entries[Math.Max(0, index)]);
    }

    private static IPAddress? ParseEntry(string entry)
    {
        var value = entry.Trim().Trim('"');
        if (value.StartsWith('['))
        {
            var end = value.IndexOf(']');
            if (end > 0)
            {
                value = value[1..end];
            }
        }
        else if (value.Count(c => c == ':') == 1)
        {
            value = value[..value.IndexOf(':')]; // IPv4 with port
        }

        if (!IPAddress.TryParse(value, out var ip))
        {
            return null;
        }

        return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
    }
}
