#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Udap.Server.Validation;

namespace Udap.Tefca.Server;

/// <summary>
/// Verifies the <c>tefca_ias</c> <c>id_token</c>: its issuer must be one of
/// <see cref="TefcaValidationOptions.TrustedIasIssuers"/>, its signature must verify with that issuer's keys (read
/// from the issuer's OpenID Connect discovery document), and it must be within its lifetime. When
/// <see cref="TefcaValidationOptions.IasIdTokenAudiences"/> is set, <c>aud</c> must match one of them.
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
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = ClockSkew,
            ValidateAudience = _options.IasIdTokenAudiences.Count > 0,
            ValidAudiences = _options.IasIdTokenAudiences
        };

        var result = await handler.ValidateTokenAsync(idToken, parameters);
        if (!result.IsValid)
        {
            _logger.LogWarning(result.Exception, "tefca_ias id_token from {Issuer} failed validation", issuer);
            return Reject("TEFCA 'tefca_ias' id_token is not valid");
        }

        return AuthorizationExtensionValidationResult.Success();
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
