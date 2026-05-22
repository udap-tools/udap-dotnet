using Udap.Client;
using Xunit;

namespace UdapMetadata.Tests.Client;
public class DiscoveryUrlTests
{
    [Fact]
    public void TestCommunityParsingWithFullCommunityUrl()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4/.well-known/udap?community=udap://fhirlabs.net/");

        Assert.Equal("https://fhirlabs.net/fhir/r4/.well-known/udap?community=udap://fhirlabs.net/", result.Url);
        Assert.Equal("https://fhirlabs.net/fhir/r4", result.Authority);
    }

    [Fact]
    public void TestCommunityParsingWithCommunityParam()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4", null, "udap://fhirlabs.net/");

        Assert.Equal("https://fhirlabs.net/fhir/r4/.well-known/udap?community=udap://fhirlabs.net/", result.Url);
        Assert.Equal("https://fhirlabs.net/fhir/r4", result.Authority);
    }
}
