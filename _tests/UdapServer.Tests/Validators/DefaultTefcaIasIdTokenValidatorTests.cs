#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Tefca.Server;
using Xunit;

namespace UdapServer.Tests.Validators;

public class DefaultTefcaIasIdTokenValidatorTests
{
    private const string Issuer = "https://ias.example.org";

    private static readonly RSA SigningKey = RSA.Create(2048);
    private static readonly RsaSecurityKey SecurityKey = new(SigningKey) { KeyId = "ias-key-1" };

    [Fact]
    public async Task Token_from_a_trusted_issuer_with_a_valid_signature_is_accepted()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), null!);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_from_an_issuer_not_in_the_trusted_list_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { "https://other.example.org" } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), null!);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("not trusted", result.ErrorDescription);
    }

    [Fact]
    public async Task With_no_trusted_issuers_every_token_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions());

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), null!);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Token_signed_with_another_key_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });
        var otherKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "ias-key-1" };

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, otherKey), null!);

        Assert.False(result.IsValid);
        Assert.Contains("not valid", result.ErrorDescription);
    }

    [Fact]
    public async Task Expired_token_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, expires: DateTime.UtcNow.AddMinutes(-30)), null!);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Audience_is_checked_when_configured()
    {
        var options = new TefcaValidationOptions { TrustedIasIssuers = { Issuer }, IasIdTokenAudiences = { "expected-client" } };
        var validator = CreateValidator(options);

        var wrongAudience = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, audience: "someone-else"), null!);
        var rightAudience = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, audience: "expected-client"), null!);

        Assert.False(wrongAudience.IsValid);
        Assert.True(rightAudience.IsValid);
    }

    [Fact]
    public async Task Value_that_is_not_a_jwt_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync("not-a-jwt", null!);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Verification_can_be_turned_off()
    {
        var validator = CreateValidator(new TefcaValidationOptions { RequireVerifiedIasIdToken = false });

        var result = await validator.ValidateAsync("not-a-jwt", null!);

        Assert.True(result.IsValid);
    }

    private static DefaultTefcaIasIdTokenValidator CreateValidator(TefcaValidationOptions options)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new IssuerHandler()));

        return new DefaultTefcaIasIdTokenValidator(Options.Create(options), factory, NullLogger<DefaultTefcaIasIdTokenValidator>.Instance);
    }

    private static string CreateIdToken(string issuer, SecurityKey key, DateTime? expires = null, string audience = "client-app")
    {
        var now = DateTime.UtcNow;
        var expiry = expires ?? now.AddMinutes(5);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(new[] { new Claim("sub", "patient-123") }),
            NotBefore = expiry.AddMinutes(-10),
            IssuedAt = expiry.AddMinutes(-10),
            Expires = expiry,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });
    }

    /// <summary>Serves the issuer's discovery document and JWKS.</summary>
    private sealed class IssuerHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body;
            if (request.RequestUri!.AbsolutePath.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
            {
                body = JsonSerializer.Serialize(new Dictionary<string, object>
                {
                    ["issuer"] = Issuer,
                    ["jwks_uri"] = Issuer + "/jwks"
                });
            }
            else if (request.RequestUri.AbsolutePath == "/jwks")
            {
                var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(SigningKey.ExportParameters(false)) { KeyId = SecurityKey.KeyId });
                body = JsonSerializer.Serialize(new { keys = new[] { new { kty = jwk.Kty, kid = jwk.Kid, n = jwk.N, e = jwk.E, use = "sig", alg = "RS256" } } });
            }
            else
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
        }
    }
}
