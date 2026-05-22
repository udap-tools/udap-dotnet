#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Udap.Client;

namespace Udap.Common.Tests.Client;

public class PkceTests
{
    [Fact]
    public void CodeVerifier_IsNotEmpty()
    {
        var pkce = new Pkce();

        Assert.NotEmpty(pkce.CodeVerifier);
    }

    [Fact]
    public void CodeChallenge_IsNotEmpty()
    {
        var pkce = new Pkce();

        Assert.NotEmpty(pkce.CodeChallenge);
    }

    [Fact]
    public void CodeVerifier_MeetsRfc7636MinLength()
    {
        var pkce = new Pkce();

        Assert.True(pkce.CodeVerifier.Length >= 43);
    }

    [Fact]
    public void CodeVerifier_MeetsRfc7636MaxLength()
    {
        var pkce = new Pkce();

        Assert.True(pkce.CodeVerifier.Length <= 128);
    }

    [Fact]
    public void CodeChallenge_IsSha256OfCodeVerifier()
    {
        var pkce = new Pkce();

        var expectedChallenge = Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.UTF8.GetBytes(pkce.CodeVerifier)));

        Assert.Equal(expectedChallenge, pkce.CodeChallenge);
    }

    [Fact]
    public void CodeVerifier_IsBase64UrlEncoded_NoPadding()
    {
        var pkce = new Pkce();

        Assert.DoesNotContain("=", pkce.CodeVerifier);
        Assert.DoesNotContain("+", pkce.CodeVerifier);
        Assert.DoesNotContain("/", pkce.CodeVerifier);
    }

    [Fact]
    public void CodeChallenge_IsBase64UrlEncoded_NoPadding()
    {
        var pkce = new Pkce();

        Assert.DoesNotContain("=", pkce.CodeChallenge);
        Assert.DoesNotContain("+", pkce.CodeChallenge);
        Assert.DoesNotContain("/", pkce.CodeChallenge);
    }

    [Fact]
    public void EachInstance_GeneratesUniqueValues()
    {
        var pkce1 = new Pkce();
        var pkce2 = new Pkce();

        Assert.NotEqual(pkce1.CodeVerifier, pkce2.CodeVerifier);
        Assert.NotEqual(pkce1.CodeChallenge, pkce2.CodeChallenge);
    }
}
