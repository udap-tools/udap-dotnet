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
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Validation;
using Udap.Tefca.Server;
using Xunit;

namespace UdapServer.Tests.Validators;

public class DefaultTefcaIasIdTokenValidatorTests
{
    private const string Issuer = "https://ias.example.org";
    private const string ProviderOid = "2.999.2";
    private const string ProviderAudience = "urn:oid:" + ProviderOid;

    private static readonly RSA SigningKey = RSA.Create(2048);
    private static readonly RsaSecurityKey SecurityKey = new(SigningKey) { KeyId = "ias-key-1" };

    [Fact]
    public async Task Token_from_a_trusted_issuer_with_a_valid_signature_is_accepted()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), Context());

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_from_an_issuer_not_in_the_trusted_list_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { "https://other.example.org" } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), Context());

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("not trusted", result.ErrorDescription);
    }

    [Fact]
    public async Task With_no_trusted_issuers_every_token_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions());

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), Context());

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Token_signed_with_another_key_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });
        var otherKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "ias-key-1" };

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, otherKey), Context());

        Assert.False(result.IsValid);
        Assert.Contains("not valid", result.ErrorDescription);
    }

    [Fact]
    public async Task Expired_token_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, expires: DateTime.UtcNow.AddMinutes(-30)), Context());

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Token_issued_to_another_ias_provider_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, audience: "urn:oid:2.999.3"), Context());

        Assert.False(result.IsValid);
        Assert.Contains("not valid", result.ErrorDescription);
    }

    [Theory]
    [InlineData("Organization/" + ProviderOid)]
    [InlineData("https://directory.example.org/fhir/Organization/" + ProviderOid)]
    public async Task Audience_comes_from_the_hl7_b2b_organization_id(string organizationId)
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var typed = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), Context(organizationId));
        var json = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), JsonContext(organizationId));

        Assert.True(typed.IsValid);
        Assert.True(json.IsValid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("2.999.2")]
    [InlineData("Organization/not-an-oid")]
    [InlineData("Location/2.999.2")]
    public async Task Request_without_a_usable_organization_id_is_rejected(string? organizationId)
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), Context(organizationId));

        Assert.False(result.IsValid);
        Assert.Contains("organization_id", result.ErrorDescription);
    }

    [Fact]
    public async Task Request_without_hl7_b2b_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });
        var context = Context();
        context.Extensions = new Dictionary<string, object>();

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey), context);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Authorization_code_without_hl7_b2b_checks_everything_but_the_audience()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });
        var context = Context();
        context.Extensions = new Dictionary<string, object>();
        context.GrantType = "authorization_code";

        var accepted = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, audience: "urn:oid:2.999.3"), context);
        var forged = await validator.ValidateAsync(CreateIdToken(Issuer, new RsaSecurityKey(RSA.Create(2048)) { KeyId = "ias-key-1" }), context);

        Assert.True(accepted.IsValid);
        Assert.False(forged.IsValid);
    }

    [Fact]
    public async Task Authorization_code_with_hl7_b2b_still_checks_the_audience()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });
        var context = Context();
        context.GrantType = "authorization_code";

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, audience: "urn:oid:2.999.3"), context);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Token_not_signed_with_rs256_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync(CreateIdToken(Issuer, SecurityKey, algorithm: SecurityAlgorithms.RsaSha512), Context());

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Value_that_is_not_a_jwt_is_rejected()
    {
        var validator = CreateValidator(new TefcaValidationOptions { TrustedIasIssuers = { Issuer } });

        var result = await validator.ValidateAsync("not-a-jwt", Context());

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Verification_can_be_turned_off()
    {
        var validator = CreateValidator(new TefcaValidationOptions { RequireVerifiedIasIdToken = false });

        var result = await validator.ValidateAsync("not-a-jwt", Context());

        Assert.True(result.IsValid);
    }

    private static UdapAuthorizationExtensionValidationContext Context(string? organizationId = "Organization/" + ProviderOid)
    {
        return NewContext(new HL7B2BAuthorizationExtension { OrganizationId = organizationId });
    }

    private static UdapAuthorizationExtensionValidationContext JsonContext(string organizationId)
    {
        return NewContext(JsonSerializer.SerializeToElement(new Dictionary<string, object> { ["organization_id"] = organizationId }));
    }

    private static UdapAuthorizationExtensionValidationContext NewContext(object b2b)
    {
        var assertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor { Issuer = "client", Audience = "token" });
        return new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = new JsonWebToken(assertion),
            ClientId = "client",
            Extensions = new Dictionary<string, object> { [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b }
        };
    }

    private static DefaultTefcaIasIdTokenValidator CreateValidator(TefcaValidationOptions options)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new IssuerHandler()));

        return new DefaultTefcaIasIdTokenValidator(Options.Create(options), factory, NullLogger<DefaultTefcaIasIdTokenValidator>.Instance);
    }

    private static string CreateIdToken(string issuer, SecurityKey key, DateTime? expires = null, string audience = ProviderAudience, string algorithm = SecurityAlgorithms.RsaSha256)
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
            SigningCredentials = new SigningCredentials(key, algorithm)
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
