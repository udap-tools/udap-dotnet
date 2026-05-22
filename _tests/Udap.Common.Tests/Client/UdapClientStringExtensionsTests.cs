#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Client.Extensions;

namespace Udap.Common.Tests.Client;

public class UdapClientStringExtensionsTests
{
    [Fact]
    public void AssertUri_ValidHttpsUri_ReturnsUri()
    {
        var result = "https://fhirlabs.net".AssertUri();

        Assert.Equal("https://fhirlabs.net", result);
    }

    [Fact]
    public void AssertUri_ValidHttpUri_ReturnsUri()
    {
        var result = "http://localhost:5001".AssertUri();

        Assert.Equal("http://localhost:5001", result);
    }

    [Fact]
    public void AssertUri_ValidUriWithPath_ReturnsUri()
    {
        var result = "https://fhirlabs.net/fhir/r4".AssertUri();

        Assert.Equal("https://fhirlabs.net/fhir/r4", result);
    }

    [Fact]
    public void AssertUri_InvalidUri_ThrowsUriFormatException()
    {
        Assert.Throws<UriFormatException>(() => "not-a-uri".AssertUri());
    }

    [Fact]
    public void AssertUri_NullUri_ThrowsUriFormatException()
    {
        string? uri = null;

        Assert.Throws<UriFormatException>(() => uri.AssertUri());
    }

    [Fact]
    public void AssertUri_EmptyString_ThrowsUriFormatException()
    {
        Assert.Throws<UriFormatException>(() => "".AssertUri());
    }

    [Fact]
    public void AssertUri_RelativeUri_ThrowsUriFormatException()
    {
        Assert.Throws<UriFormatException>(() => "fhir/r4".AssertUri());
    }
}
