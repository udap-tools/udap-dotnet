#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using Udap.Server.Configuration;
using Udap.Server.Hosting;

namespace UdapServer.Tests.Middleware;

public class OutboundConnectGuardTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.255")]
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("198.18.0.1")]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    [InlineData("ff02::1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("64:ff9b::a00:1")]
    [InlineData("2002:a00:1::")]
    public void Non_public_addresses_are_not_public(string address)
    {
        Assert.False(OutboundConnectGuard.IsPublic(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("172.32.0.1")]
    [InlineData("100.128.0.1")]
    [InlineData("192.169.0.1")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::ffff:8.8.8.8")]
    public void Public_addresses_are_public(string address)
    {
        Assert.True(OutboundConnectGuard.IsPublic(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("idp.internal", "idp.internal", 443, true)]
    [InlineData("IDP.internal", "idp.internal", 8443, true)]
    [InlineData("idp.internal:8443", "idp.internal", 8443, true)]
    [InlineData("idp.internal:8443", "idp.internal", 443, false)]
    [InlineData("idp.internal", "other.internal", 443, false)]
    [InlineData("fd00::1", "fd00::1", 443, true)]
    [InlineData("[fd00::1]:8443", "[fd00::1]", 8443, true)]
    [InlineData("[fd00::1]:8443", "[fd00::1]", 443, false)]
    public void Allow_list_matches_host_and_optional_port(string entry, string host, int port, bool expected)
    {
        var options = new OutboundConnectionOptions { AllowedPrivateHosts = { entry } };

        Assert.Equal(expected, OutboundConnectGuard.IsAllowListed(options, host, port));
    }

    [Fact]
    public async Task Connect_to_a_private_literal_is_refused_before_any_socket_is_opened()
    {
        var options = new OutboundConnectionOptions();

        var ex = await Assert.ThrowsAsync<HttpRequestException>(() =>
            OutboundConnectGuard.ConnectAsync(new DnsEndPoint("169.254.169.254", 80), options, allowLoopback: false, CancellationToken.None).AsTask());

        Assert.Contains("non-public", ex.Message);
    }

    [Fact]
    public async Task Connect_to_loopback_is_refused_unless_loopback_is_allowed()
    {
        var options = new OutboundConnectionOptions();

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            OutboundConnectGuard.ConnectAsync(new DnsEndPoint("127.0.0.1", 1), options, allowLoopback: false, CancellationToken.None).AsTask());

        // Allowed: the guard passes it on, and the connection itself then fails (nothing listens on port 1).
        var ex = await Assert.ThrowsAnyAsync<Exception>(() =>
            OutboundConnectGuard.ConnectAsync(new DnsEndPoint("127.0.0.1", 1), options, allowLoopback: true, CancellationToken.None).AsTask());
        Assert.IsNotType<HttpRequestException>(ex);
    }

    [Fact]
    public async Task Allow_listed_private_host_is_passed_through()
    {
        var options = new OutboundConnectionOptions { AllowedPrivateHosts = { "127.0.0.1:1" } };

        var ex = await Assert.ThrowsAnyAsync<Exception>(() =>
            OutboundConnectGuard.ConnectAsync(new DnsEndPoint("127.0.0.1", 1), options, allowLoopback: false, CancellationToken.None).AsTask());
        Assert.IsNotType<HttpRequestException>(ex);
    }
}
