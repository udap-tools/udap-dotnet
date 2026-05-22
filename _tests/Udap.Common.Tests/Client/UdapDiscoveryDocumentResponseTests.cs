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
using Duende.IdentityModel.Client;
using Udap.Client.Messages;
using DiscoveryPolicy = Udap.Client.DiscoveryPolicy;

namespace Udap.Common.Tests.Client;

public class UdapDiscoveryDocumentResponseTests
{
    [Fact]
    public async Task InitializeAsync_PolicyViolation_SetsErrorTypeAndMessage()
    {
        var json = """
        {
            "token_endpoint": "http://evil.example.com/token",
            "registration_endpoint": "https://fhirlabs.net/connect/register"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            RequireHttps = true,
            AllowHttpOnLoopback = false,
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.True(disco.IsError);
        Assert.Equal(ResponseErrorType.PolicyViolation, disco.ErrorType);
        Assert.Contains("HTTPS", disco.Error!);
    }

    [Fact]
    public async Task InitializeAsync_ValidEndpoints_NoError()
    {
        var json = """
        {
            "token_endpoint": "https://fhirlabs.net/connect/token",
            "registration_endpoint": "https://fhirlabs.net/connect/register"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            RequireHttps = true,
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.False(disco.IsError);
    }

    [Fact]
    public async Task InitializeAsync_FailedHttpResponse_SetsErrorMessage()
    {
        var httpResponse = new HttpResponseMessage(HttpStatusCode.NotFound);

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, "Resource not found");

        Assert.True(disco.IsError);
        Assert.Equal("Resource not found", disco.Error);
    }

    [Fact]
    public async Task InitializeAsync_EndpointOnDifferentHost_PolicyViolation()
    {
        var json = """
        {
            "token_endpoint": "https://other-host.com/token"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.True(disco.IsError);
        Assert.Equal(ResponseErrorType.PolicyViolation, disco.ErrorType);
        Assert.Contains("different host", disco.Error!);
    }

    [Fact]
    public async Task InitializeAsync_NullInitializationData_CreatesDefaultPolicy()
    {
        var json = """
        {
            "signed_metadata": "eyJhbGciOiJSUzI1NiJ9.test.sig"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = false
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.NotNull(disco.Policy);
        Assert.False(disco.IsError);
        Assert.Equal("https://fhirlabs.net", disco.Policy.Authority);
    }

    [Fact]
    public async Task InitializeAsync_MultipleAdditionalBaseAddresses_AllResolved()
    {
        var json = """
        {
            "token_endpoint": "https://auth.partner.com/connect/token",
            "registration_endpoint": "https://reg.partner.com/connect/register"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = true,
            AdditionalEndpointBaseAddresses =
            {
                "https://auth.partner.com",
                "https://reg.partner.com"
            }
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.False(disco.IsError);
    }

    [Fact]
    public async Task InitializeAsync_ValidateEndpointsFalse_SkipsHostValidation()
    {
        var json = """
        {
            "token_endpoint": "https://other-host.com/token"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = false
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.False(disco.IsError);
    }

    [Fact]
    public async Task ValidateEndpoints_JwksUri_IsValidated()
    {
        var json = """
        {
            "jwks_uri": "http://evil.example.com/keys"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            RequireHttps = true,
            AllowHttpOnLoopback = false,
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.True(disco.IsError);
        Assert.Contains("HTTPS", disco.Error!);
    }

    [Fact]
    public async Task ValidateEndpoints_CheckSessionIframe_IsValidated()
    {
        var json = """
        {
            "check_session_iframe": "http://evil.example.com/session"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            RequireHttps = true,
            AllowHttpOnLoopback = false,
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.True(disco.IsError);
        Assert.Contains("HTTPS", disco.Error!);
    }

    [Fact]
    public async Task ValidateEndpoints_EmptyEndpointValue_ReturnsMissingError()
    {
        var json = """
        {
            "token_endpoint": ""
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.True(disco.IsError);
        Assert.Contains("Malformed endpoint", disco.Error!);
    }

    [Fact]
    public async Task ValidateEndpoints_InvalidScheme_ReturnsMalformedError()
    {
        var json = """
        {
            "token_endpoint": "ftp://fhirlabs.net/token"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.True(disco.IsError);
        Assert.Contains("Malformed endpoint", disco.Error!);
    }

    [Fact]
    public async Task ValidateEndpoints_AuthorityValidationStrategyFails_ReturnsError()
    {
        var json = """
        {
            "token_endpoint": "https://fhirlabs.net/other-path/token"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net/connect",
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.True(disco.IsError);
    }

    [Fact]
    public async Task ValidateEndpoints_NonEndpointProperty_IsIgnored()
    {
        var json = """
        {
            "signed_metadata": "some-jwt-value",
            "udap_versions_supported": ["1"],
            "token_endpoint": "https://fhirlabs.net/connect/token"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = true
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.False(disco.IsError);
    }

    [Fact]
    public async Task InitializeAsync_AdditionalEndpointBaseAddresses_AllowsOtherHost()
    {
        var json = """
        {
            "token_endpoint": "https://auth.partner.com/connect/token"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = true,
            AdditionalEndpointBaseAddresses = { "https://auth.partner.com" }
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.False(disco.IsError);
    }

    [Fact]
    public async Task InitializeAsync_EndpointOnExcludeList_SkipsValidation()
    {
        var json = """
        {
            "token_endpoint": "https://completely-different.com/token"
        }
        """;

        var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        var policy = new DiscoveryPolicy
        {
            Authority = "https://fhirlabs.net",
            ValidateEndpoints = true,
            EndpointValidationExcludeList = { "token_endpoint" }
        };

        var disco = await ProtocolResponse.FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(
            httpResponse, policy);

        Assert.False(disco.IsError);
    }
}
