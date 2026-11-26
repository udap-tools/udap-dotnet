#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Udap.Server.Configuration;

namespace Udap.Server.Hosting;

/// <summary>
/// Builds HTTP handlers that refuse to connect to non-public addresses unless <see cref="OutboundConnectionOptions"/>
/// allows them. The check runs on the resolved address at connect time and the socket connects to that same address,
/// so a redirect hop or a DNS answer that changes between checks cannot reach an internal host.
/// </summary>
public static class OutboundConnectGuard
{
    /// <summary>
    /// A <see cref="SocketsHttpHandler"/> whose connections are checked by <see cref="ConnectAsync"/>.
    /// </summary>
    public static SocketsHttpHandler CreateHandler(OutboundConnectionOptions options, IHostEnvironment? environment, bool allowAutoRedirect = true)
    {
        var allowLoopback = options.AllowLoopback ?? environment?.IsDevelopment() == true;

        return new SocketsHttpHandler
        {
            AllowAutoRedirect = allowAutoRedirect,
            // Long-lived clients: recycling connections lets DNS changes through, and each new connection is checked.
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectCallback = (context, token) => ConnectAsync(context.DnsEndPoint, options, allowLoopback, token)
        };
    }

    /// <summary>
    /// Resolves the endpoint, refuses it if any address is not allowed, and connects to the checked addresses.
    /// </summary>
    public static async ValueTask<Stream> ConnectAsync(
        DnsEndPoint endPoint,
        OutboundConnectionOptions options,
        bool allowLoopback,
        CancellationToken token)
    {
        var host = endPoint.Host;
        var port = endPoint.Port;

        var addresses = IPAddress.TryParse(host.Trim('[', ']'), out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, token).ConfigureAwait(false);

        if (addresses.Length == 0)
        {
            throw new HttpRequestException($"Outbound connection refused: {host} did not resolve.");
        }

        if (options.BlockNonPublicAddresses && !IsAllowListed(options, host, port))
        {
            // Every address must pass: a name that resolves to one public and one internal address is refused.
            var blocked = addresses.FirstOrDefault(a => !IsPublic(a) && !(allowLoopback && IsLoopback(a)));
            if (blocked != null)
            {
                throw new HttpRequestException(
                    $"Outbound connection refused: {host} resolves to the non-public address {blocked}. " +
                    $"Add the host to {OutboundConnectionOptions.SectionName}:{nameof(OutboundConnectionOptions.AllowedPrivateHosts)} if this is intended.");
            }
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, port, token).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// True when the host, with its port if the entry names one, is in <see cref="OutboundConnectionOptions.AllowedPrivateHosts"/>.
    /// </summary>
    public static bool IsAllowListed(OutboundConnectionOptions options, string host, int port)
    {
        foreach (var entry in options.AllowedPrivateHosts)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            var value = entry.Trim();
            string entryHost = value;
            int? entryPort = null;

            // "host:port", but not a bare IPv6 literal ("fd00::1"); a bracketed one may carry a port ("[fd00::1]:8443").
            var colon = value.LastIndexOf(':');
            if (colon > 0 && (value.IndexOf(':') == colon || value.StartsWith('[')) &&
                int.TryParse(value[(colon + 1)..], out var parsedPort))
            {
                entryHost = value[..colon];
                entryPort = parsedPort;
            }

            if (string.Equals(entryHost.Trim('[', ']'), host.Trim('[', ']'), StringComparison.OrdinalIgnoreCase) &&
                (entryPort == null || entryPort == port))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>True for loopback addresses (127.0.0.0/8, ::1), including IPv4-mapped forms.</summary>
    public static bool IsLoopback(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return IPAddress.IsLoopback(address);
    }

    /// <summary>
    /// True when the address is globally routable: not loopback, private, link-local, carrier-grade NAT,
    /// unspecified, multicast, broadcast, reserved or unique-local. IPv6 forms that embed an IPv4 address
    /// (IPv4-mapped, NAT64, 6to4) are judged by the embedded address.
    /// </summary>
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return IsPublicIPv4(address.GetAddressBytes());
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        var b = address.GetAddressBytes();

        if (address.Equals(IPAddress.IPv6Loopback) || address.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        // fe80::/10 link-local, fec0::/10 site-local (deprecated), fc00::/7 unique local, ff00::/8 multicast
        if (b[0] == 0xfe && (b[1] & 0xc0) is 0x80 or 0xc0) return false;
        if ((b[0] & 0xfe) == 0xfc) return false;
        if (b[0] == 0xff) return false;

        // 64:ff9b::/96 NAT64: judge the embedded IPv4 address
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b.Skip(4).Take(8).All(x => x == 0))
        {
            return IsPublicIPv4(b[12..16]);
        }

        // 2002::/16 6to4: judge the embedded IPv4 address
        if (b[0] == 0x20 && b[1] == 0x02)
        {
            return IsPublicIPv4(b[2..6]);
        }

        // ::/96 IPv4-compatible (deprecated) and the rest of ::/8
        if (b[0] == 0x00)
        {
            return false;
        }

        return true;
    }

    private static bool IsPublicIPv4(byte[] b)
    {
        return !(
            b[0] == 0 ||                                   // 0.0.0.0/8 "this network"
            b[0] == 10 ||                                  // 10.0.0.0/8 private
            b[0] == 127 ||                                 // 127.0.0.0/8 loopback
            (b[0] == 100 && (b[1] & 0xc0) == 64) ||        // 100.64.0.0/10 carrier-grade NAT
            (b[0] == 169 && b[1] == 254) ||                // 169.254.0.0/16 link-local, cloud metadata
            (b[0] == 172 && (b[1] & 0xf0) == 16) ||        // 172.16.0.0/12 private
            (b[0] == 192 && b[1] == 0 && b[2] == 0) ||     // 192.0.0.0/24 IETF protocol assignments
            (b[0] == 192 && b[1] == 168) ||                // 192.168.0.0/16 private
            (b[0] == 198 && (b[1] & 0xfe) == 18) ||        // 198.18.0.0/15 benchmarking
            b[0] >= 224);                                  // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, broadcast
    }
}
