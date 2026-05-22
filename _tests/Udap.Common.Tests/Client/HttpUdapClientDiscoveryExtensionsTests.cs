#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text;
using Udap.Client.Extensions;
using Udap.Client.Messages;

namespace Udap.Common.Tests.Client;

public class HttpUdapClientDiscoveryExtensionsTests
{
    private static readonly string ValidDiscoJson = """
        {
            "udap_versions_supported": ["1"],
            "signed_metadata": "test-jwt"
        }
        """;

    #region GetUdapDiscoveryDocument — address handling

    [Fact]
    public async Task GetUdapDiscoveryDocument_WithAddress_Succeeds()
    {
        var client = CreateClient(HttpStatusCode.OK, ValidDiscoJson);

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net/fhir/r4");

        Assert.False(disco.IsError, disco.Error);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_UsesBaseAddress_WhenNoAddressProvided()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, ValidDiscoJson);
        var client = new HttpClient(handler) { BaseAddress = new Uri("https://fhirlabs.net/fhir/r4") };

        var disco = await client.GetUdapDiscoveryDocument();

        Assert.False(disco.IsError, disco.Error);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_NoAddressOrBaseAddress_Throws()
    {
        var client = CreateClient(HttpStatusCode.OK, ValidDiscoJson);

        await Assert.ThrowsAsync<ArgumentException>(
            () => client.GetUdapDiscoveryDocument());
    }

    #endregion

    #region GetUdapDiscoveryDocument — HTTPS enforcement

    [Fact]
    public async Task GetUdapDiscoveryDocument_HttpUrl_RequireHttps_ReturnsError()
    {
        var client = CreateClient(HttpStatusCode.OK, ValidDiscoJson);

        var request = new UdapDiscoveryDocumentRequest
        {
            Address = "http://fhirlabs.net/fhir/r4",
            Policy = { RequireHttps = true, AllowHttpOnLoopback = false }
        };

        var disco = await client.GetUdapDiscoveryDocument(request);

        Assert.True(disco.IsError);
        Assert.Contains("HTTPS required", disco.Error);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_HttpOnLocalhost_Allowed()
    {
        var client = CreateClient(HttpStatusCode.OK, ValidDiscoJson);

        var request = new UdapDiscoveryDocumentRequest
        {
            Address = "http://localhost/fhir/r4",
            Policy = { RequireHttps = true, AllowHttpOnLoopback = true }
        };

        var disco = await client.GetUdapDiscoveryDocument(request);

        Assert.False(disco.IsError, disco.Error);
    }

    #endregion

    #region GetUdapDiscoveryDocument — error responses

    [Fact]
    public async Task GetUdapDiscoveryDocument_ServerReturns404_ReturnsError()
    {
        var client = CreateClient(HttpStatusCode.NotFound, "Not Found");

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net/fhir/r4");

        Assert.True(disco.IsError);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_ServerReturns500_ReturnsError()
    {
        var client = CreateClient(HttpStatusCode.InternalServerError, """{"error":"server_error"}""");

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net/fhir/r4");

        Assert.True(disco.IsError);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_NetworkException_ReturnsError()
    {
        var client = new HttpClient(new ThrowingHandler());

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net/fhir/r4");

        Assert.True(disco.IsError);
        Assert.Contains("Error connecting to", disco.Error);
    }

    #endregion

    #region GetUdapDiscoveryDocument — policy and community

    [Fact]
    public async Task GetUdapDiscoveryDocument_SetsAuthorityFromParsedUrl()
    {
        var client = CreateClient(HttpStatusCode.OK, ValidDiscoJson);

        var request = new UdapDiscoveryDocumentRequest
        {
            Address = "https://fhirlabs.net/fhir/r4"
        };

        var disco = await client.GetUdapDiscoveryDocument(request);

        Assert.False(disco.IsError, disco.Error);
        Assert.Equal("https://fhirlabs.net/fhir/r4", request.Policy.Authority);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_WithCommunity_IncludesInUrl()
    {
        string? capturedUrl = null;
        var handler = new CapturingHandler(HttpStatusCode.OK, ValidDiscoJson,
            req => capturedUrl = req.RequestUri?.ToString());
        var client = new HttpClient(handler);

        var request = new UdapDiscoveryDocumentRequest
        {
            Address = "https://fhirlabs.net/fhir/r4",
            Community = "udap://fhirlabs.net"
        };

        await client.GetUdapDiscoveryDocument(request);

        Assert.NotNull(capturedUrl);
        Assert.Contains("community=udap://fhirlabs.net", capturedUrl);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_PreservesExistingAuthority()
    {
        var client = CreateClient(HttpStatusCode.OK, ValidDiscoJson);

        var request = new UdapDiscoveryDocumentRequest
        {
            Address = "https://fhirlabs.net/fhir/r4",
            Policy = { Authority = "https://custom-authority.com" }
        };

        var disco = await client.GetUdapDiscoveryDocument(request);

        Assert.Equal("https://custom-authority.com", request.Policy.Authority);
    }

    #endregion

    #region GetUdapDiscoveryDocument — JWK endpoint

    [Fact]
    public async Task GetUdapDiscoveryDocument_WithJwksUri_FetchesKeySet()
    {
        var discoJson = """
        {
            "udap_versions_supported": ["1"],
            "signed_metadata": "test-jwt",
            "jwks_uri": "https://fhirlabs.net/.well-known/jwks"
        }
        """;

        var jwksJson = """{"keys":[]}""";

        var handler = new MultiResponseHandler(new Dictionary<string, (HttpStatusCode, string)>
        {
            { "/.well-known/udap", (HttpStatusCode.OK, discoJson) },
            { "/.well-known/jwks", (HttpStatusCode.OK, jwksJson) }
        });

        var client = new HttpClient(handler);

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net");

        Assert.False(disco.IsError, disco.Error);
        Assert.NotNull(disco.KeySet);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_JwksFetchFails_WithHttpResponse_ReturnsError()
    {
        var discoJson = """
        {
            "udap_versions_supported": ["1"],
            "signed_metadata": "test-jwt",
            "jwks_uri": "https://fhirlabs.net/.well-known/jwks"
        }
        """;

        var handler = new MultiResponseHandler(new Dictionary<string, (HttpStatusCode, string)>
        {
            { "/.well-known/udap", (HttpStatusCode.OK, discoJson) },
            { "/.well-known/jwks", (HttpStatusCode.InternalServerError, "error") }
        });

        var client = new HttpClient(handler);

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net");

        Assert.True(disco.IsError);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_JwksFetchThrows_ReturnsError()
    {
        var discoJson = """
        {
            "udap_versions_supported": ["1"],
            "signed_metadata": "test-jwt",
            "jwks_uri": "https://fhirlabs.net/.well-known/jwks"
        }
        """;

        var handler = new MultiResponseHandler(
            new Dictionary<string, (HttpStatusCode, string)>
            {
                { "/.well-known/udap", (HttpStatusCode.OK, discoJson) }
            },
            throwOnMiss: true);

        var client = new HttpClient(handler);

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net");

        Assert.True(disco.IsError);
        Assert.Contains("Error connecting to", disco.Error);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_OuterCancellation_Rethrows()
    {
        var client = new HttpClient(new CancellingHandler());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.GetUdapDiscoveryDocument("https://fhirlabs.net"));
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_JwksCancellation_Rethrows()
    {
        var discoJson = """
        {
            "udap_versions_supported": ["1"],
            "signed_metadata": "test-jwt",
            "jwks_uri": "https://fhirlabs.net/.well-known/jwks"
        }
        """;

        var handler = new MultiResponseHandler(
            new Dictionary<string, (HttpStatusCode, string)>
            {
                { "/.well-known/udap", (HttpStatusCode.OK, discoJson) }
            },
            cancelOnMiss: true);

        var client = new HttpClient(handler);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.GetUdapDiscoveryDocument("https://fhirlabs.net"));
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_DiscoIsError_ReturnsEarly()
    {
        var discoJson = """
        {
            "udap_versions_supported": ["1"],
            "signed_metadata": "test-jwt",
            "token_endpoint": "ftp://invalid/token"
        }
        """;

        var client = CreateClient(HttpStatusCode.OK, discoJson);

        var request = new UdapDiscoveryDocumentRequest
        {
            Address = "https://fhirlabs.net",
            Policy = { ValidateEndpoints = true }
        };

        var disco = await client.GetUdapDiscoveryDocument(request);

        Assert.True(disco.IsError);
    }

    [Fact]
    public async Task GetUdapDiscoveryDocument_NoJwksUri_ReturnsWithoutKeySet()
    {
        var client = CreateClient(HttpStatusCode.OK, ValidDiscoJson);

        var disco = await client.GetUdapDiscoveryDocument("https://fhirlabs.net");

        Assert.False(disco.IsError, disco.Error);
        Assert.Null(disco.KeySet);
    }

    #endregion

    #region Helpers

    private static HttpClient CreateClient(HttpStatusCode statusCode, string responseBody)
    {
        return new HttpClient(new FakeHandler(statusCode, responseBody));
    }

    private class FakeHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _body;

        public FakeHandler(HttpStatusCode statusCode, string body)
        {
            _statusCode = statusCode;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
        }
    }

    private class CapturingHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _body;
        private readonly Action<HttpRequestMessage> _onSend;

        public CapturingHandler(HttpStatusCode statusCode, string body, Action<HttpRequestMessage> onSend)
        {
            _statusCode = statusCode;
            _body = body;
            _onSend = onSend;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _onSend(request);
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
        }
    }

    private class MultiResponseHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, (HttpStatusCode Status, string Body)> _responses;
        private readonly bool _throwOnMiss;
        private readonly bool _cancelOnMiss;

        public MultiResponseHandler(
            Dictionary<string, (HttpStatusCode, string)> responses,
            bool throwOnMiss = false,
            bool cancelOnMiss = false)
        {
            _responses = responses;
            _throwOnMiss = throwOnMiss;
            _cancelOnMiss = cancelOnMiss;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.AbsolutePath ?? "";

            foreach (var kvp in _responses)
            {
                if (path.Contains(kvp.Key))
                {
                    return Task.FromResult(new HttpResponseMessage(kvp.Value.Status)
                    {
                        Content = new StringContent(kvp.Value.Body, Encoding.UTF8, "application/json")
                    });
                }
            }

            if (_cancelOnMiss)
                throw new OperationCanceledException("Cancelled");
            if (_throwOnMiss)
                throw new InvalidOperationException("Simulated JWK fetch failure");

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException("Network failure");
        }
    }

    private class CancellingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new OperationCanceledException("Request cancelled");
        }
    }

    #endregion
}
