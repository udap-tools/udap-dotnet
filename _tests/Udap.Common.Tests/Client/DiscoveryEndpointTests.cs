#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Client;

namespace Udap.Common.Tests.Client;

public class DiscoveryEndpointTests
{
    #region IsValidScheme

    [Fact]
    public void IsValidScheme_HttpsUrl_ReturnsTrue()
    {
        var uri = new Uri("https://fhirlabs.net");
        Assert.True(DiscoveryEndpoint.IsValidScheme(uri));
    }

    [Fact]
    public void IsValidScheme_HttpUrl_ReturnsTrue()
    {
        var uri = new Uri("http://fhirlabs.net");
        Assert.True(DiscoveryEndpoint.IsValidScheme(uri));
    }

    [Fact]
    public void IsValidScheme_FtpUrl_ReturnsFalse()
    {
        var uri = new Uri("ftp://fhirlabs.net");
        Assert.False(DiscoveryEndpoint.IsValidScheme(uri));
    }

    [Fact]
    public void IsValidScheme_NullUrl_ReturnsFalse()
    {
        Assert.False(DiscoveryEndpoint.IsValidScheme(null));
    }

    [Fact]
    public void IsValidScheme_CaseInsensitive()
    {
        var uri = new Uri("HTTPS://fhirlabs.net");
        Assert.True(DiscoveryEndpoint.IsValidScheme(uri));
    }

    #endregion

    #region IsSecureScheme

    [Fact]
    public void IsSecureScheme_HttpsUrl_ReturnsTrue()
    {
        var uri = new Uri("https://fhirlabs.net");
        var policy = new DiscoveryPolicy { RequireHttps = true };

        Assert.True(DiscoveryEndpoint.IsSecureScheme(uri, policy));
    }

    [Fact]
    public void IsSecureScheme_HttpUrl_RequireHttps_ReturnsFalse()
    {
        var uri = new Uri("http://fhirlabs.net");
        var policy = new DiscoveryPolicy { RequireHttps = true, AllowHttpOnLoopback = false };

        Assert.False(DiscoveryEndpoint.IsSecureScheme(uri, policy));
    }

    [Fact]
    public void IsSecureScheme_HttpNotRequired_ReturnsTrue()
    {
        var uri = new Uri("http://fhirlabs.net");
        var policy = new DiscoveryPolicy { RequireHttps = false };

        Assert.True(DiscoveryEndpoint.IsSecureScheme(uri, policy));
    }

    [Fact]
    public void IsSecureScheme_HttpOnLocalhost_AllowLoopback_ReturnsTrue()
    {
        var uri = new Uri("http://localhost/fhir/r4");
        var policy = new DiscoveryPolicy { RequireHttps = true, AllowHttpOnLoopback = true };

        Assert.True(DiscoveryEndpoint.IsSecureScheme(uri, policy));
    }

    [Fact]
    public void IsSecureScheme_HttpOn127001_AllowLoopback_ReturnsTrue()
    {
        var uri = new Uri("http://127.0.0.1/fhir/r4");
        var policy = new DiscoveryPolicy { RequireHttps = true, AllowHttpOnLoopback = true };

        Assert.True(DiscoveryEndpoint.IsSecureScheme(uri, policy));
    }

    [Fact]
    public void IsSecureScheme_HttpOnRemoteHost_AllowLoopback_ReturnsFalse()
    {
        var uri = new Uri("http://fhirlabs.net/fhir/r4");
        var policy = new DiscoveryPolicy { RequireHttps = true, AllowHttpOnLoopback = true };

        Assert.False(DiscoveryEndpoint.IsSecureScheme(uri, policy));
    }

    #endregion

    #region ParseUrl

    [Fact]
    public void ParseUrl_SimpleBaseUrl_AppendsDiscoveryPath()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4");

        Assert.Equal("https://fhirlabs.net/fhir/r4", result.Authority);
        Assert.Contains(".well-known/udap", result.Url);
    }

    [Fact]
    public void ParseUrl_UrlAlreadyContainsDiscoveryEndpoint_ExtractsAuthority()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.Equal("https://fhirlabs.net/fhir/r4", result.Authority);
        Assert.Equal("https://fhirlabs.net/fhir/r4/.well-known/udap", result.Url);
    }

    [Fact]
    public void ParseUrl_WithCommunity_AppendsCommunityQueryParam()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4", community: "udap://fhirlabs.net");

        Assert.Contains("?community=udap://fhirlabs.net", result.Url);
    }

    [Fact]
    public void ParseUrl_WithCustomPath_UsesCustomPath()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net", path: ".well-known/custom");

        Assert.Contains(".well-known/custom", result.Url);
    }

    [Fact]
    public void ParseUrl_MalformedUrl_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => DiscoveryEndpoint.ParseUrl("not-a-url"));
    }

    [Fact]
    public void ParseUrl_FtpScheme_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => DiscoveryEndpoint.ParseUrl("ftp://fhirlabs.net"));
    }

    [Fact]
    public void ParseUrl_TrailingSlash_HandledCorrectly()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4/");

        Assert.Equal("https://fhirlabs.net/fhir/r4", result.Authority);
    }

    [Fact]
    public void ParseUrl_WithPort_ParsesCorrectly()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://localhost:5001/fhir/r4");

        Assert.Equal("https://localhost:5001/fhir/r4", result.Authority);
        Assert.Contains(".well-known/udap", result.Url);
    }

    [Fact]
    public void ParseUrl_PathWithLeadingSlash_StripsIt()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net", path: "/.well-known/udap");

        Assert.Contains(".well-known/udap", result.Url);
        Assert.DoesNotContain("//.well-known", result.Url);
    }

    #endregion

    #region Constructor

    [Fact]
    public void Constructor_SetsAuthorityAndUrl()
    {
        var endpoint = new DiscoveryEndpoint("https://fhirlabs.net", "https://fhirlabs.net/.well-known/udap");

        Assert.Equal("https://fhirlabs.net", endpoint.Authority);
        Assert.Equal("https://fhirlabs.net/.well-known/udap", endpoint.Url);
    }

    #endregion
}
