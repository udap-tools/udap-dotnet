#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using Microsoft.Extensions.Options;
using Udap.Client;
using Udap.Client.Configuration;

namespace Udap.Common.Tests.Client;

public class HeaderAugmentationHandlerTests
{
    [Fact]
    public async Task SendAsync_WithHeaders_AddsHeadersToRequest()
    {
        var options = new UdapClientOptions
        {
            Headers = new Dictionary<string, string>
            {
                { "USER_KEY", "hobojoe" },
                { "ORG_KEY", "travelOrg" }
            }
        };

        var monitor = new TestOptionsMonitor(options);
        var handler = new HeaderAugmentationHandler(monitor)
        {
            InnerHandler = new FakeInnerHandler()
        };

        var client = new HttpClient(handler);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://fhirlabs.net/fhir/r4");

        await client.SendAsync(request);

        Assert.True(request.Headers.Contains("USER_KEY"));
        Assert.Equal("hobojoe", request.Headers.GetValues("USER_KEY").Single());
        Assert.True(request.Headers.Contains("ORG_KEY"));
        Assert.Equal("travelOrg", request.Headers.GetValues("ORG_KEY").Single());
    }

    [Fact]
    public async Task SendAsync_NullHeaders_DoesNotThrow()
    {
        var options = new UdapClientOptions { Headers = null };
        var monitor = new TestOptionsMonitor(options);
        var handler = new HeaderAugmentationHandler(monitor)
        {
            InnerHandler = new FakeInnerHandler()
        };

        var client = new HttpClient(handler);
        var response = await client.GetAsync("https://fhirlabs.net/fhir/r4");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SendAsync_EmptyHeaders_DoesNotAddHeaders()
    {
        var options = new UdapClientOptions { Headers = new Dictionary<string, string>() };
        var monitor = new TestOptionsMonitor(options);
        var handler = new HeaderAugmentationHandler(monitor)
        {
            InnerHandler = new FakeInnerHandler()
        };

        var client = new HttpClient(handler);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://fhirlabs.net/fhir/r4");
        await client.SendAsync(request);

        Assert.False(request.Headers.Contains("USER_KEY"));
    }

    private class FakeInnerHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private class TestOptionsMonitor : IOptionsMonitor<UdapClientOptions>
    {
        public TestOptionsMonitor(UdapClientOptions value) => CurrentValue = value;
        public UdapClientOptions CurrentValue { get; }
        public UdapClientOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<UdapClientOptions, string?> listener) => null;
    }
}
