#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Model;
using Udap.Server.Configuration;
using Udap.Server.Extensions;
using Udap.Server.Storage;
using Udap.Server.Storage.Extensions;
using Udap.Server.Storage.Stores;
using Udap.Util.Extensions;

namespace Udap.Server.Validation.Default;

/// <summary>
/// Validates a secret based on UDAP.  <a href="Udap.org"/>
/// </summary>
public class UdapJwtSecretValidator : ISecretValidator
{
    private readonly IIssuerNameService _issuerNameService;
    private readonly IReplayCache _replayCache;
    private readonly IServerUrls _urls;
    private readonly IdentityServerOptions _options;
    private readonly TrustChainValidator _trustChainValidator;
    private readonly IUdapClientRegistrationStore _clientStore;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ServerSettings _serverSettings;
    private readonly ILogger _logger;

    private const string Purpose = nameof(UdapJwtSecretValidator);

    public UdapJwtSecretValidator(
        IIssuerNameService issuerNameService,
        IReplayCache replayCache,
        IServerUrls urls,
        IdentityServerOptions options,
        TrustChainValidator trustChainValidator,
        IUdapClientRegistrationStore clientStore,
        IHttpContextAccessor httpContextAccessor,
        ServerSettings serverSettings,
        ILogger<UdapJwtSecretValidator> logger)
    {
        _issuerNameService = issuerNameService;
        _replayCache = replayCache;
        _urls = urls;
        _options = options;
        _trustChainValidator = trustChainValidator;
        _clientStore = clientStore;
        _httpContextAccessor = httpContextAccessor;
        _serverSettings = serverSettings;

        _logger = logger;
    }
    
    /// <summary>Validates a secret</summary>
    /// <param name="secrets">The stored secrets.</param>
    /// <param name="parsedSecret">The received secret.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>A validation result</returns>
    public async Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets, ParsedSecret parsedSecret, CancellationToken ct)
    {
        var fail = new SecretValidationResult { Success = false };
        var success = new SecretValidationResult { Success = true };
        
        // Never the credential itself: it is the client assertion.
        _logger.LogDebug("Parsed secret of type {SecretType} for client_id: {ClientId}", parsedSecret.Type, parsedSecret.Id);

        if (parsedSecret.Type != IdentityServerConstants.ParsedSecretTypes.JwtBearer)
        {
            return fail;
        }

        if (parsedSecret.Credential is not string clientAssertion)
        {
            _logger.LogError("ParsedSecret.Credential is not a string.");
            return fail;
        }

        // Without an x5c header this is not a UDAP client assertion (e.g. private_key_jwt against a
        // registered JWKS). Decline quietly so the next secret validator decides: recording an error
        // description here would leave it on the request, where the token response middleware would
        // attach it to an unrelated error once another validator has authenticated the client.
        if (!HasX5cHeader(clientAssertion))
        {
            _logger.LogDebug("Client assertion for client_id {ClientId} has no x5c header; not a UDAP client assertion", parsedSecret.Id);
            return fail;
        }

        var tokenHandler = new JsonWebTokenHandler() { MaximumTokenSizeInBytes = _options.InputLengthRestrictions.Jwt };

        var tokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKeys = parsedSecret.GetUdapKeys(),
            ValidateIssuerSigningKey = true,

            ValidIssuer = parsedSecret.Id,
            ValidateIssuer = true,

            ValidateAudience = true,
            ValidAudience = _httpContextAccessor.HttpContext?.Request.GetDisplayUrl(),
            
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            
            ValidAlgorithms =
            [
                UdapConstants.SupportedAlgorithm.RS256, UdapConstants.SupportedAlgorithm.RS384,
                UdapConstants.SupportedAlgorithm.ES256, UdapConstants.SupportedAlgorithm.ES384
            ],

            ClockSkew = TimeSpan.FromMinutes(5),

            ValidateSignatureLast = true
        };
        
        var result = await tokenHandler.ValidateTokenAsync(clientAssertion, tokenValidationParameters);
        
        if (!result.IsValid)
        {
            _logger.LogError(result.Exception, "JWT token validation error for client_id: {ClientId}", parsedSecret.Id);

            var jsonWebToken = tokenHandler.ReadJsonWebToken(clientAssertion);

            if (!jsonWebToken!.TryGetHeaderValue(JwtHeaderParameterNames.Alg, out string _))
            {
                _logger.LogError("Missing jwt alg claim in header for client_id: {ClientId}", parsedSecret.Id);
            }

            if (!jsonWebToken.TryGetHeaderValue(JwtHeaderParameterNames.X5c, out string _))
            {
                _logger.LogError("Missing jwt x5c claim in header for client_id: {ClientId}", parsedSecret.Id);
            }

            SetErrorDescription("Client assertion JWT validation failed");
            return fail;
        }

        var jwtToken = (JsonWebToken)result.SecurityToken;

        if (jwtToken.Subject != jwtToken.Issuer)
        {
            _logger.LogError("Both 'sub' and 'iss' in the client assertion token must have a value of client_id.");
            SetErrorDescription("Both 'sub' and 'iss' in the client assertion token must have a value of client_id");
            return fail;
        }

        var exp = jwtToken.ValidTo;
        if (exp == DateTime.MinValue)
        {
            _logger.LogError("exp is missing.");
            SetErrorDescription("exp claim is missing from client assertion");
            return fail;
        }

        // UDAP JWT-Based Client Authentication section 6.3: a maximum AnT lifetime of 5 minutes is RECOMMENDED.
        // TokenValidationParameters only checks that exp has not already passed, so bound exp against iat here.
        var iat = jwtToken.IssuedAt;
        if (_serverSettings.ClientAssertionMaxLifetimeSeconds > 0
            && iat != DateTime.MinValue
            && exp > iat.AddSeconds(_serverSettings.ClientAssertionMaxLifetimeSeconds))
        {
            _logger.LogError("Client assertion exp exceeds the maximum lifetime of {MaxLifetimeSeconds} seconds from iat for client_id: {ClientId}. iat={Iat:O} exp={Exp:O}",
                _serverSettings.ClientAssertionMaxLifetimeSeconds, parsedSecret.Id, iat, exp);
            SetErrorDescription($"Client assertion exp exceeds the maximum lifetime of {_serverSettings.ClientAssertionMaxLifetimeSeconds} seconds from iat");
            return fail;
        }

        var jti = jwtToken.Id;
        if (jti.IsMissing())
        {
            _logger.LogError("jti is missing.");
            SetErrorDescription("jti claim is missing from client assertion");
            return fail;
        }

        if (await _replayCache.ExistsAsync(Purpose, jti, ct))
        {
            _logger.LogError("jti is found in replay cache. Possible replay attack.");
            SetErrorDescription("jti is found in replay cache. Possible replay attack");
            return fail;
        }
        else
        {
            await _replayCache.AddAsync(Purpose, jti, exp.AddMinutes(5), ct);
        }

        var udapSecret = parsedSecret.ToModel();
        var endCertificate = udapSecret.GetUdapEndCert();

        if (endCertificate == null)
        {
            _logger.LogError("Client assertion x5c header does not contain a certificate for client_id: {ClientId}", parsedSecret.Id);
            SetErrorDescription("Client assertion x5c header does not contain a certificate");
            return fail;
        }

        // Give a precise reason before chain building would otherwise report a generic failure.
        var now = DateTime.UtcNow;
        if (endCertificate.NotAfter.ToUniversalTime() < now || endCertificate.NotBefore.ToUniversalTime() > now)
        {
            _logger.LogError(
                "Client certificate is outside its validity period (NotBefore: {NotBefore:u}, NotAfter: {NotAfter:u}) for client_id: {ClientId}",
                endCertificate.NotBefore.ToUniversalTime(), endCertificate.NotAfter.ToUniversalTime(), parsedSecret.Id);
            SetErrorDescription(
                $"Client certificate is outside its validity period (NotBefore: {endCertificate.NotBefore.ToUniversalTime():u}, " +
                $"NotAfter: {endCertificate.NotAfter.ToUniversalTime():u}). Register again with a current certificate");
            return fail;
        }

        IList<X509Certificate2>? certChainList;
        // Duende removes expired secrets before calling this validator, so this list may be
        // missing the UDAP_SAN_URI_ISS_NAME / UDAP_COMMUNITY secrets even though they exist.
        var secretList = secrets.ToList();

        try
        {
            certChainList = await secretList.GetUdapChainsAsync(_clientStore);

            if (certChainList == null || certChainList.Count == 0)
            {
                //
                // Self-heal: the client's UDAP identity secrets have expired (typically the client
                // certificate was renewed and the registration was updated or never re-registered).
                // Roll the stored secrets forward to the certificate presented in this assertion.
                // The presented certificate is fully chain-validated below before success is returned.
                //
                _logger.LogInformation(
                    "UDAP identity secrets are missing or expired for client_id: {ClientId}. Attempting secret rollover.",
                    parsedSecret.Id);

                var rolledSecrets = await _clientStore.RolloverClientSecrets(udapSecret, ct);

                if (rolledSecrets == null || rolledSecrets.Count == 0)
                {
                    _logger.LogWarning("Could not roll secrets for client_id: {ClientId}", parsedSecret.Id);
                }
                else
                {
                    secretList = rolledSecrets.ToList();
                    certChainList = await secretList.GetUdapChainsAsync(_clientStore);
                }
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Could not resolve secrets for client_id: {ClientId}", parsedSecret.Id);
            SetErrorDescription("Could not resolve client registration secrets");
            return fail;
        }

        if (certChainList == null || certChainList.Count == 0)
        {
            var description = DescribeMissingTrustAnchors(secretList);
            _logger.LogError("{Description} for client_id: {ClientId}", description, parsedSecret.Id);
            SetErrorDescription(description);
            return fail;
        }

        // The certificate must be this client's: UDAP JWT-Based Client Authentication section 6.3 requires
        // a uniformResourceIdentifier SAN equal to the issuer the client registered with. A certificate that
        // only chains to the same community belongs to some other client.
        var registeredIssuer = secretList
            .FirstOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
            ?.Value;

        if (registeredIssuer == null || !endCertificate.HasUriSubjectAltName(registeredIssuer))
        {
            _logger.LogError(
                "Client certificate URI SANs [{CertificateSans}] do not include the registered issuer {RegisteredIssuer} for client_id: {ClientId}",
                string.Join(", ", endCertificate.GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI).Select(san => san.Item2)),
                registeredIssuer, parsedSecret.Id);
            SetErrorDescription("Client certificate does not match the certificate the client registered with");
            return fail;
        }

        //
        // PKI chain validation, including CRL checking
        //
        if (!await _trustChainValidator.IsTrustedCertificateAsync(
                parsedSecret.Id,
                endCertificate,
                new X509Certificate2Collection(certChainList.ToArray()),
                new X509Certificate2Collection(certChainList.ToRootCertArray())))
        {
            SetErrorDescription("Certificate chain validation failed");
            return fail;
        }

        return success;
    }

    /// <summary>
    /// Explains why no trust anchors could be resolved, so the client can act on the error_description.
    /// </summary>
    private static string DescribeMissingTrustAnchors(IReadOnlyCollection<Secret> secretList)
    {
        var hasIssuer = secretList.Any(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME);
        var community = secretList.FirstOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)?.Value;

        if (!hasIssuer || community == null)
        {
            return "Client registration has no valid UDAP community secrets (missing or expired) and they could not be " +
                   "rolled forward. Cancel the registration and register again with the current client certificate";
        }

        return $"No trust anchors are configured for the client's community (community id {community}). " +
               "Contact the authorization server administrator";
    }

    // Reads the JOSE header directly so a header the token handler cannot parse, or an x5c of any JSON
    // shape, never throws here; the full validation below reports anything malformed.
    private static bool HasX5cHeader(string clientAssertion)
    {
        var dot = clientAssertion.IndexOf('.');
        if (dot <= 0)
        {
            return false;
        }

        try
        {
            var header = Base64UrlEncoder.DecodeBytes(clientAssertion[..dot]);
            using var doc = JsonDocument.Parse(header);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                   && doc.RootElement.TryGetProperty(JwtHeaderParameterNames.X5c, out _);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void SetErrorDescription(string description)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext != null)
        {
            httpContext.Items[UdapServerConstants.HttpContextItems.UdapErrorDescription] = description;
        }
    }
}