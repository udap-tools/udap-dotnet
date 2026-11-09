#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client;
using Udap.Model;

namespace Udap.Common.Tests.Client;

public class SignedMetadataEndpointsTests
{
    private const string Token = "https://as.example/connect/token";
    private const string Register = "https://as.example/connect/register";
    private const string Authorize = "https://as.example/connect/authorize";

    // Resolve only reads claims (the signature is validated earlier), so an unsigned JWT is enough here.
    private static string Jwt(Dictionary<string, object> claims) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor { Claims = claims });

    private static DiscoveryPolicy Policy(bool validateEndpoints = false) => new()
    {
        Authority = "https://fhir.example/fhir/r4",
        ValidateEndpoints = validateEndpoints
    };

    private static Dictionary<string, object> AllClaims() => new()
    {
        [UdapConstants.Discovery.TokenEndpoint] = Token,
        [UdapConstants.Discovery.RegistrationEndpoint] = Register,
        [UdapConstants.Discovery.AuthorizationEndpoint] = Authorize
    };

    [Fact]
    public void SignedValuesWinOverPlainJson()
    {
        var plain = new UdapMetadata
        {
            TokenEndpoint = "https://attacker.example/token",
            RegistrationEndpoint = "https://attacker.example/register",
            AuthorizationEndpoint = "https://attacker.example/authorize"
        };

        var endpoints = SignedMetadataEndpoints.Resolve(Jwt(AllClaims()), plain, Policy(), NullLogger.Instance);
        SignedMetadataEndpoints.Apply(plain, endpoints);

        Assert.Equal(Token, plain.TokenEndpoint);
        Assert.Equal(Register, plain.RegistrationEndpoint);
        Assert.Equal(Authorize, plain.AuthorizationEndpoint);
    }

    [Theory]
    [InlineData(UdapConstants.Discovery.TokenEndpoint)]
    [InlineData(UdapConstants.Discovery.RegistrationEndpoint)]
    public void MissingRequiredClaimIsRejected(string claim)
    {
        var claims = AllClaims();
        claims.Remove(claim);

        var ex = Assert.Throws<SecurityTokenException>(() =>
            SignedMetadataEndpoints.Resolve(Jwt(claims), new UdapMetadata(), Policy(), NullLogger.Instance));
        Assert.Contains(claim, ex.Message);
    }

    [Fact]
    public void AuthorizationClaimRequiredWhenPlainJsonHasOne()
    {
        var claims = AllClaims();
        claims.Remove(UdapConstants.Discovery.AuthorizationEndpoint);

        Assert.Throws<SecurityTokenException>(() => SignedMetadataEndpoints.Resolve(
            Jwt(claims), new UdapMetadata { AuthorizationEndpoint = Authorize }, Policy(), NullLogger.Instance));

        var endpoints = SignedMetadataEndpoints.Resolve(Jwt(claims), new UdapMetadata(), Policy(), NullLogger.Instance);
        Assert.False(endpoints.ContainsKey(UdapConstants.Discovery.AuthorizationEndpoint));
    }

    [Fact]
    public void PlainHttpSignedEndpointIsRejected()
    {
        var claims = AllClaims();
        claims[UdapConstants.Discovery.RegistrationEndpoint] = "http://as.example/connect/register";

        var ex = Assert.Throws<SecurityTokenException>(() =>
            SignedMetadataEndpoints.Resolve(Jwt(claims), new UdapMetadata(), Policy(), NullLogger.Instance));
        Assert.Contains("HTTPS", ex.Message);
    }

    [Fact]
    public void HostRuleAppliesToSignedEndpointsWhenEnabled()
    {
        Assert.Throws<SecurityTokenException>(() => SignedMetadataEndpoints.Resolve(
            Jwt(AllClaims()), new UdapMetadata(), Policy(validateEndpoints: true), NullLogger.Instance));
    }
}
