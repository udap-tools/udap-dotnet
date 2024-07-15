using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Udap.Client.Client;

namespace Udap.Common.Tests.Client;
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
