#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Util.Extensions;
using Xunit;

namespace Udap.Common.Tests.Util;

public class StringExtensionsTests
{
    [Fact]
    public void ToCrLf_LfOnly_ConvertsToCrLf()
    {
        var input = "line1\nline2\nline3";
        var result = input.ToCrLf();
        Assert.Equal("line1\r\nline2\r\nline3", result);
    }

    [Fact]
    public void ToCrLf_CrOnly_ConvertsToCrLf()
    {
        var input = "line1\rline2\rline3";
        var result = input.ToCrLf();
        Assert.Equal("line1\r\nline2\r\nline3", result);
    }

    [Fact]
    public void ToCrLf_MixedLineEndings_NormalizesToCrLf()
    {
        var input = "line1\r\nline2\nline3\rline4";
        var result = input.ToCrLf();
        Assert.Equal("line1\r\nline2\r\nline3\r\nline4", result);
    }

    [Fact]
    public void ToCrLf_AlreadyCrLf_Unchanged()
    {
        var input = "line1\r\nline2\r\nline3";
        var result = input.ToCrLf();
        Assert.Equal(input, result);
    }

    [Fact]
    public void ToLf_CrLfInput_ConvertsToLf()
    {
        var input = "line1\r\nline2\r\nline3";
        var result = input.ToLf();
        Assert.Equal("line1\nline2\nline3", result);
    }

    [Fact]
    public void ToLf_CrOnly_ConvertsToLf()
    {
        var input = "line1\rline2\rline3";
        var result = input.ToLf();
        Assert.Equal("line1\nline2\nline3", result);
    }

    [Fact]
    public void FromSpaceSeparatedString_MultipleValues_SplitsCorrectly()
    {
        var result = "openid profile email".FromSpaceSeparatedString().ToList();
        Assert.Equal(3, result.Count);
        Assert.Equal("openid", result[0]);
        Assert.Equal("profile", result[1]);
        Assert.Equal("email", result[2]);
    }

    [Fact]
    public void FromSpaceSeparatedString_ExtraSpaces_TrimsAndSplits()
    {
        var result = "  openid   profile  ".FromSpaceSeparatedString().ToList();
        Assert.Equal(2, result.Count);
        Assert.Equal("openid", result[0]);
        Assert.Equal("profile", result[1]);
    }

    [Fact]
    public void FromSpaceSeparatedString_SingleValue_ReturnsSingleItem()
    {
        var result = "openid".FromSpaceSeparatedString().ToList();
        Assert.Single(result);
        Assert.Equal("openid", result[0]);
    }

    [Fact]
    public void DecodeJwtHeader_ValidBase64Url_DecodesCorrectly()
    {
        // {"alg":"RS256"} base64url-encoded
        var encoded = "eyJhbGciOiJSUzI1NiJ9";
        var result = encoded.DecodeJwtHeader();
        Assert.Contains("RS256", result);
    }

    [Fact]
    public void ToSpaceSeparatedString_ICollection_NullReturnsEmpty()
    {
        ICollection<string>? list = null;
        Assert.Equal(string.Empty, list.ToSpaceSeparatedString());
    }

    [Fact]
    public void ToSpaceSeparatedString_ICollection_EmptyReturnsEmpty()
    {
        ICollection<string> list = new List<string>();
        Assert.Equal(string.Empty, list.ToSpaceSeparatedString());
    }

    [Fact]
    public void ToSpaceSeparatedString_ICollection_JoinsWithSpaces()
    {
        ICollection<string> list = new List<string> { "openid", "profile", "email" };
        Assert.Equal("openid profile email", list.ToSpaceSeparatedString());
    }

    [Fact]
    public void ToSpaceSeparatedString_IEnumerable_NullReturnsEmpty()
    {
        IEnumerable<string>? list = null;
        Assert.Equal(string.Empty, list.ToSpaceSeparatedString());
    }

    [Fact]
    public void ToSpaceSeparatedString_IEnumerable_JoinsWithSpaces()
    {
        IEnumerable<string> list = new[] { "a", "b", "c" };
        Assert.Equal("a b c", list.ToSpaceSeparatedString());
    }

    [Fact]
    public void IsECDSA_ES256_ReturnsTrue()
    {
        Assert.True("ES256".IsECDSA());
    }

    [Fact]
    public void IsECDSA_ES384_ReturnsTrue()
    {
        Assert.True("ES384".IsECDSA());
    }

    [Fact]
    public void IsECDSA_RS256_ReturnsFalse()
    {
        Assert.False("RS256".IsECDSA());
    }

    [Fact]
    public void IsECDSA_DoesNotMatchSubstring()
    {
        Assert.False("ECDSA".IsECDSA());
    }
}
