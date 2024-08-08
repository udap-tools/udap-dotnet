using FluentAssertions;
using Udap.Client.Client;

namespace UdapMetadata.Tests.Client;
public class DiscoveryUrlTests
{
    [Fact]
    public void TestCommunityParsingWithFullCommunityUrl()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4/.well-known/udap?community=udap://fhirlabs.net/");

        result.Url.Should().Be("https://fhirlabs.net/fhir/r4/.well-known/udap?community=udap://fhirlabs.net/");
        result.Authority.Should().Be("https://fhirlabs.net/fhir/r4");
    }

    [Fact]
    public void TestCommunityParsingWithCommunityParam()
    {
        var result = DiscoveryEndpoint.ParseUrl("https://fhirlabs.net/fhir/r4", null, "udap://fhirlabs.net/");

        result.Url.Should().Be("https://fhirlabs.net/fhir/r4/.well-known/udap?community=udap://fhirlabs.net/");
        result.Authority.Should().Be("https://fhirlabs.net/fhir/r4");
    }
}
