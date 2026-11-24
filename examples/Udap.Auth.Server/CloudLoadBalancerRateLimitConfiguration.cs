#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using AspNetCoreRateLimit;
using Microsoft.Extensions.Options;

namespace Udap.Auth.Server;

/// <summary>
/// AspNetCoreRateLimit resolver setup for Cloud Run behind Google's external Application Load Balancer.
/// <para>
/// The stock <see cref="RateLimitConfiguration"/> resolves the client from RealIpHeader (caller supplied,
/// so spoofable) and otherwise from Connection.RemoteIpAddress, which on Cloud Run is Google's internal
/// front end for every request. Either way the limits were not per real client.
/// </para>
/// <para>
/// The load balancer appends "CLIENT_IP,LOAD_BALANCER_IP" to X-Forwarded-For. This resolver takes the
/// entry just left of a configured load balancer IP, else the entry TrustedProxyHops from the right.
/// Configure with IpRateLimiting:TrustedProxyHops and IpRateLimiting:LoadBalancerIps.
/// </para>
/// </summary>
public class CloudLoadBalancerRateLimitConfiguration : RateLimitConfiguration
{
    private readonly int _trustedProxyHops;
    private readonly IPAddress[] _loadBalancerIps;

    public CloudLoadBalancerRateLimitConfiguration(
        IOptions<IpRateLimitOptions> ipOptions,
        IOptions<ClientRateLimitOptions> clientOptions,
        IConfiguration configuration)
        : base(ipOptions, clientOptions)
    {
        var section = configuration.GetSection("IpRateLimiting");
        _trustedProxyHops = section.GetValue("TrustedProxyHops", 1);
        _loadBalancerIps = (section.GetSection("LoadBalancerIps").Get<string[]>() ?? [])
            .Select(v => IPAddress.TryParse(v.Trim(), out var ip) ? ip : null)
            .Where(ip => ip != null)
            .Select(ip => ip!)
            .ToArray();
    }

    public override void RegisterResolvers()
    {
        var clientIdHeader = GetClientIdHeader();
        if (clientIdHeader != null)
        {
            ClientResolvers.Add(new ClientHeaderResolveContributor(clientIdHeader));
        }

        // Deliberately ignore RealIpHeader: it is whatever the caller sent.
        IpResolvers.Add(new ForwardedForResolveContributor(_trustedProxyHops, _loadBalancerIps));
        IpResolvers.Add(new IpConnectionResolveContributor());
    }

    private sealed class ForwardedForResolveContributor(int trustedProxyHops, IPAddress[] loadBalancerIps) : IIpResolveContributor
    {
        public string? ResolveIp(HttpContext httpContext)
        {
            var entries = httpContext.Request.Headers["X-Forwarded-For"]
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .SelectMany(v => v!.Split(','))
                .Select(e => e.Trim())
                .ToList();

            if (entries.Count == 0)
            {
                return null;
            }

            if (loadBalancerIps.Length > 0)
            {
                for (var i = entries.Count - 1; i > 0; i--)
                {
                    if (IPAddress.TryParse(entries[i], out var candidate) && loadBalancerIps.Contains(candidate))
                    {
                        return Normalize(entries[i - 1]);
                    }
                }
            }

            var index = Math.Max(0, entries.Count - 1 - Math.Max(0, trustedProxyHops));
            return Normalize(entries[index]);
        }

        private static string? Normalize(string entry)
        {
            try
            {
                return IpAddressUtil.ParseIp(entry).ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}
