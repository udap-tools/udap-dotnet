using Udap.Common.Extensions;
using Xunit;

namespace Udap.Common.Tests.Util;

public class CommonStringExtensionsTests
{
    [Fact]
    public void EnsureTrailingSlash_WithoutSlash_AddsSlash()
    {
        Assert.Equal("https://example.com/", "https://example.com".EnsureTrailingSlash());
    }

    [Fact]
    public void EnsureTrailingSlash_WithSlash_ReturnsUnchanged()
    {
        Assert.Equal("https://example.com/", "https://example.com/".EnsureTrailingSlash());
    }

    [Fact]
    public void EnsureLeadingSlash_NullUrl_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, ((string?)null).EnsureLeadingSlash());
    }

    [Fact]
    public void EnsureLeadingSlash_NoSlash_AddsSlash()
    {
        Assert.Equal("/path", "path".EnsureLeadingSlash());
    }

    [Fact]
    public void EnsureLeadingSlash_AlreadyHasSlash_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, "/path".EnsureLeadingSlash());
    }

    [Fact]
    public void IsPresent_NonEmpty_ReturnsTrue()
    {
        Assert.True("hello".IsPresent());
    }

    [Fact]
    public void IsPresent_NullOrWhitespace_ReturnsFalse()
    {
        Assert.False(((string?)null).IsPresent());
        Assert.False("".IsPresent());
        Assert.False("   ".IsPresent());
    }

    [Fact]
    public void IsMissing_NullOrWhitespace_ReturnsTrue()
    {
        Assert.True("".IsMissing());
        Assert.True("   ".IsMissing());
    }

    [Fact]
    public void IsMissing_NonEmpty_ReturnsFalse()
    {
        Assert.False("hello".IsMissing());
    }

    [Fact]
    public void RemoveTrailingSlash_WithSlash_RemovesIt()
    {
        Assert.Equal("https://example.com", "https://example.com/".RemoveTrailingSlash());
    }

    [Fact]
    public void RemoveTrailingSlash_WithoutSlash_ReturnsUnchanged()
    {
        Assert.Equal("https://example.com", "https://example.com".RemoveTrailingSlash());
    }

    [Fact]
    public void GetBaseUrlFromMetadataUrl_StripsWellKnownUdap()
    {
        Assert.Equal("https://fhir.example.com/r4", "https://fhir.example.com/r4/.well-known/udap".GetBaseUrlFromMetadataUrl());
    }

    [Fact]
    public void GetBaseUrlFromMetadataUrl_NoWellKnown_ReturnsOriginal()
    {
        Assert.Equal("https://fhir.example.com/r4", "https://fhir.example.com/r4".GetBaseUrlFromMetadataUrl());
    }

    [Fact]
    public void GetCommunityFromQueryParams_WithCommunity_ReturnsValue()
    {
        Assert.Equal("udap://fhirlabs.net", "community=udap://fhirlabs.net".GetCommunityFromQueryParams());
    }

    [Fact]
    public void GetCommunityFromQueryParams_MultipleParms_ReturnsCorrectValue()
    {
        Assert.Equal("udap://fhirlabs.net", "foo=bar&community=udap://fhirlabs.net&baz=qux".GetCommunityFromQueryParams());
    }

    [Fact]
    public void GetCommunityFromQueryParams_NoCommunity_ReturnsNull()
    {
        Assert.Null("foo=bar&baz=qux".GetCommunityFromQueryParams());
    }

    [Fact]
    public void RemoveQueryParameters_WithQueryString_StripsIt()
    {
        Assert.Equal("https://example.com/fhir/r4", "https://example.com/fhir/r4?community=udap://fhirlabs.net".RemoveQueryParameters());
    }

    [Fact]
    public void RemoveQueryParameters_NoQueryString_ReturnsPath()
    {
        Assert.Equal("https://example.com/fhir/r4", "https://example.com/fhir/r4".RemoveQueryParameters());
    }
}
