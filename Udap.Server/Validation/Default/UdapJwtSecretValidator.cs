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
        ILogger<UdapJwtSecretValidator> logger)
    {
        _issuerNameService = issuerNameService;
        _replayCache = replayCache;
        _urls = urls;
        _options = options;
        _trustChainValidator = trustChainValidator;
        _clientStore = clientStore;
        _httpContextAccessor = httpContextAccessor;

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
        
        _logger.LogDebug("Parsed secret: {ParsedSecret}", JsonSerializer.Serialize(parsedSecret));

        if (parsedSecret.Type != IdentityServerConstants.ParsedSecretTypes.JwtBearer)
        {
            return fail;
        }

        if (parsedSecret.Credential is not string clientAssertion)
        {
            _logger.LogError("ParsedSecret.Credential is not a string.");
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

        IList<X509Certificate2>? certChainList;

        try
        {
            var secretList = secrets.ToList();
            certChainList = await secretList.GetUdapChainsAsync(_clientStore);

            if (certChainList == null && secretList.Count == 0)
            {
                var rolledSecrets = await _clientStore.RolloverClientSecrets(parsedSecret.ToModel());
                if (rolledSecrets == null || rolledSecrets.Count == 0)
                {
                    _logger.LogWarning("Could not roll secret for client id: {ClientId}", parsedSecret.Id);
                }
                else
                {
                    certChainList = await rolledSecrets.GetUdapChainsAsync(_clientStore);
                }
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Could not resolve secrets");
            return fail;
        }

        if (certChainList == null || !certChainList.Any())
        {
            _logger.LogError("There are no anchors available to validate client assertion for client_id: {ClientId}", parsedSecret.Id);
            SetErrorDescription("No trust anchors available to validate client assertion");
            return fail;
        }

        //
        // PKI chain validation, including CRL checking
        //
        if (!await _trustChainValidator.IsTrustedCertificateAsync(
                parsedSecret.Id,
                parsedSecret.ToModel().GetUdapEndCert()!,
                new X509Certificate2Collection(certChainList.ToArray()),
                new X509Certificate2Collection(certChainList.ToRootCertArray())))
        {
            SetErrorDescription("Certificate chain validation failed");
            return fail;
        }

        return success;
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