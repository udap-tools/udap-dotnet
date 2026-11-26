#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Validation;

namespace Udap.Tefca.Server;

/// <summary>
/// Verifies the <c>tefca_ias</c> <c>id_token</c> as the IAS Exchange Purpose Implementation SOP v3.0 Section 4.9
/// describes it: its issuer must be one of <see cref="TefcaValidationOptions.TrustedIasIssuers"/>, it must be signed
/// with RS256 by a key from that issuer's OpenID Connect discovery document, it must be within its lifetime, and its
/// <c>aud</c> must be the requesting IAS Provider's HCID as <c>urn:oid:&lt;oid&gt;</c>. The HCID is taken from the
/// <c>hl7-b2b</c> <c>organization_id</c> of the request (<c>Organization/&lt;oid&gt;</c>).
/// Registered by <c>AddUdapTefcaValidation</c> unless the host registers its own <see cref="ITefcaIasIdTokenValidator"/>.
/// </summary>
public class DefaultTefcaIasIdTokenValidator : ITefcaIasIdTokenValidator
{
    /// <summary>Name of the HttpClient used to read issuer discovery documents and keys.</summary>
    public const string HttpClientName = "Udap.Tefca.IasIssuer";

    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    private readonly TefcaValidationOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<DefaultTefcaIasIdTokenValidator> _logger;
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _configurations = new(StringComparer.Ordinal);

    public DefaultTefcaIasIdTokenValidator(
        IOptions<TefcaValidationOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<DefaultTefcaIasIdTokenValidator> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<AuthorizationExtensionValidationResult> ValidateAsync(string idToken, UdapAuthorizationExtensionValidationContext context)
    {
        if (!_options.RequireVerifiedIasIdToken)
        {
            return AuthorizationExtensionValidationResult.Success();
        }

        var handler = new JsonWebTokenHandler();
        if (!handler.CanReadToken(idToken))
        {
            return Reject("TEFCA 'tefca_ias' id_token is not a JWT");
        }

        // The Facilitated FHIR SOP requires hl7-b2b only for client credentials. In an authorization code flow without
        // it, the patient also signs in at this server, so the audience is not checked there.
        var expectedAudience = GetRequesterAudience(context);
        var hasB2b = context?.Extensions?.ContainsKey(UdapConstants.UdapAuthorizationExtensions.Hl7B2B) == true;
        var isAuthorizationCode = string.Equals(context?.GrantType, "authorization_code", StringComparison.Ordinal);
        if (expectedAudience == null && (hasB2b || !isAuthorizationCode))
        {
            return Reject("TEFCA 'tefca_ias' requires hl7-b2b 'organization_id' naming the IAS Provider's Directory entry (Organization/<oid>)");
        }

        var issuer = handler.ReadJsonWebToken(idToken).Issuer;
        if (string.IsNullOrEmpty(issuer) || !_options.TrustedIasIssuers.Contains(issuer))
        {
            _logger.LogWarning("tefca_ias id_token issuer {Issuer} is not in TrustedIasIssuers", issuer);
            return Reject("TEFCA 'tefca_ias' id_token issuer is not trusted");
        }

        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await GetConfigurationManager(issuer).GetConfigurationAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read the signing keys of tefca_ias issuer {Issuer}", issuer);
            return Reject("TEFCA 'tefca_ias' id_token issuer keys could not be read");
        }

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidateIssuer = true,
            IssuerSigningKeys = configuration.SigningKeys,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = ClockSkew,
            ValidateAudience = expectedAudience != null,
            ValidAudience = expectedAudience
        };

        var result = await handler.ValidateTokenAsync(idToken, parameters);
        if (!result.IsValid)
        {
            _logger.LogWarning(result.Exception, "tefca_ias id_token from {Issuer} failed validation", issuer);
            return Reject("TEFCA 'tefca_ias' id_token is not valid");
        }

        return AuthorizationExtensionValidationResult.Success();
    }

    /// <summary>
    /// The audience an IAS id_token must carry for this request: <c>urn:oid:</c> plus the OID in the hl7-b2b
    /// <c>organization_id</c>, or null when the request does not name one.
    /// </summary>
    private static string? GetRequesterAudience(UdapAuthorizationExtensionValidationContext? context)
    {
        if (context?.Extensions == null
            || !context.Extensions.TryGetValue(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, out var b2bValue))
        {
            return null;
        }

        var organizationId = b2bValue switch
        {
            HL7B2BAuthorizationExtension b2b => b2b.OrganizationId,
            JsonElement { ValueKind: JsonValueKind.Object } json
                when json.TryGetProperty(UdapConstants.HL7B2BAuthorizationExtension.OrganizationId, out var value)
                && value.ValueKind == JsonValueKind.String => value.GetString(),
            _ => null
        };

        if (string.IsNullOrWhiteSpace(organizationId))
        {
            return null;
        }

        var oid = organizationId.TrimEnd('/');
        var slash = oid.LastIndexOf('/');
        if (slash < 0 || !oid.AsSpan(0, slash).EndsWith("Organization", StringComparison.Ordinal))
        {
            return null;
        }

        oid = oid[(slash + 1)..];
        return IsOid(oid) ? "urn:oid:" + oid : null;
    }

    private static bool IsOid(string value)
    {
        if (value.Length == 0 || value[0] == '.' || value[^1] == '.' || value.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c != '.' && !char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return value.Contains('.');
    }

    private ConfigurationManager<OpenIdConnectConfiguration> GetConfigurationManager(string issuer)
    {
        return _configurations.GetOrAdd(issuer, iss =>
        {
            var metadataAddress = iss.TrimEnd('/') + "/.well-known/openid-configuration";
            var retriever = new HttpDocumentRetriever(_httpClientFactory.CreateClient(HttpClientName)) { RequireHttps = true };
            return new ConfigurationManager<OpenIdConnectConfiguration>(metadataAddress, new OpenIdConnectConfigurationRetriever(), retriever);
        });
    }

    private static AuthorizationExtensionValidationResult Reject(string description)
        => AuthorizationExtensionValidationResult.Failure("invalid_grant", description);
}
