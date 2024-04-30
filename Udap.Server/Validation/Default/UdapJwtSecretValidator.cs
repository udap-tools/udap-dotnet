#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Model;
using Udap.Server.Configuration;
using Udap.Server.Extensions;
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
    private TrustChainValidator _trustChainValidator;
    private readonly ServerSettings _serverSettings;
    private readonly IUdapClientRegistrationStore _clientStore;
    private readonly ILogger _logger;

    private const string Purpose = nameof(UdapJwtSecretValidator);

    public UdapJwtSecretValidator(
        IIssuerNameService issuerNameService,
        IReplayCache replayCache,
        IServerUrls urls,
        IdentityServerOptions options,
        TrustChainValidator trustChainValidator,
        ServerSettings serverSettings,
        IUdapClientRegistrationStore clientStore,
        ILogger<UdapJwtSecretValidator> logger)
    {
        _issuerNameService = issuerNameService;
        _replayCache = replayCache;
        _urls = urls;
        _options = options;
        _trustChainValidator = trustChainValidator;
        _serverSettings = serverSettings;
        _clientStore = clientStore;

        _logger = logger;
    }


    //Todo: Write workflow diagrams to describe this process

    /// <summary>Validates a secret</summary>
    /// <param name="secrets">The stored secrets.</param>
    /// <param name="parsedSecret">The received secret.</param>
    /// <returns>A validation result</returns>
    public async Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets, ParsedSecret parsedSecret)
    {
        var fail = new SecretValidationResult { Success = false };
        var success = new SecretValidationResult { Success = true };

        await Task.Delay(50);

        _logger.LogDebug($"parsedSecret {JsonSerializer.Serialize(parsedSecret)}");

        // return success;

        if (parsedSecret.Type != IdentityServerConstants.ParsedSecretTypes.JwtBearer)
        {
            return fail;
        }

        if (!(parsedSecret.Credential is string jwtTokenString))
        {
            _logger.LogError("ParsedSecret.Credential is not a string.");
            return fail;
        }

        IList<X509Certificate2>? certChainList;

        try
        {
            certChainList = await secrets.GetUdapChainsAsync(_clientStore);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Could not parse secrets");
            return fail;
        }

        if (certChainList != null && !certChainList.Any())
        {
            _logger.LogError($"There are no anchors available to validate client assertion for cient_id: {parsedSecret.Id}");

            return fail;
        }
        
        var validAudiences = new[]
        {
                // token endpoint URL
                string.Concat(_urls.BaseUrl.EnsureTrailingSlash(), Constants.ProtocolRoutePaths.Token),
                // TODO: remove the issuer URL in a future major release?
                // issuer URL
                string.Concat((await _issuerNameService.GetCurrentAsync()).EnsureTrailingSlash(), Constants.ProtocolRoutePaths.Token)
        }.Distinct();

        var tokenHandler = new JsonWebTokenHandler() { MaximumTokenSizeInBytes = _options.InputLengthRestrictions.Jwt };
        
        var tokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKeys = parsedSecret.GetUdapKeys(),
            ValidateIssuerSigningKey = true,

            ValidIssuer = parsedSecret.Id,
            ValidateIssuer = true,

            ValidAudiences = validAudiences,
            ValidateAudience = true,

            RequireSignedTokens = true,
            RequireExpirationTime = true,

            ValidAlgorithms =  new[] { 
                UdapConstants.SupportedAlgorithm.RS256, UdapConstants.SupportedAlgorithm.RS384,
                UdapConstants.SupportedAlgorithm.ES256, UdapConstants.SupportedAlgorithm.ES384 },

            ClockSkew = TimeSpan.FromMinutes(5),

            ValidateSignatureLast = true
        };
        
        var result = tokenHandler.ValidateToken(jwtTokenString, tokenValidationParameters);
        
        if (!result.IsValid)
        {
            _logger.LogError(result.Exception, "JWT token validation error");

            var jsonWebToken = tokenHandler.ReadJsonWebToken(jwtTokenString);

            if (!jsonWebToken!.TryGetHeaderValue(JwtHeaderParameterNames.Alg, out string _))
            {
                _logger.LogError($"Missing jwt x5c claim in header for client_id: {parsedSecret.Id}");
            }

            if (!jsonWebToken!.TryGetHeaderValue(JwtHeaderParameterNames.X5c, out string _))
            {
                _logger.LogError($"Missing jwt x5c claim in header for client_id: {parsedSecret.Id}");
            }

            return fail;
        }

        var jwtToken = (JsonWebToken)result.SecurityToken;

        
        if (jwtToken.Subject != jwtToken.Issuer)
        {
            _logger.LogError("Both 'sub' and 'iss' in the client assertion token must have a value of client_id.");
            return fail;
        }
            

        var exp = jwtToken.ValidTo;
        if (exp == DateTime.MinValue)
        {
            _logger.LogError("exp is missing.");
            return fail;
        }

        var jti = jwtToken.Id;
        if (jti.IsMissing())
        {
            _logger.LogError("jti is missing.");
            return fail;
        }

        if (await _replayCache.ExistsAsync(Purpose, jti))
        {
            _logger.LogError("jti is found in replay cache. Possible replay attack.");
            return fail;
        }
        else
        {
            await _replayCache.AddAsync(Purpose, jti, exp.AddMinutes(5));
        }

        //
        // PKI chain validation, including CRL checking
        //
        if (_trustChainValidator.IsTrustedCertificate(
                parsedSecret.Id,
                parsedSecret.GetUdapEndCertAsync(),
                new X509Certificate2Collection(certChainList.ToArray()),
                new X509Certificate2Collection(certChainList.ToRootCertArray()),
                out X509ChainElementCollection? _,
                out _))
        {
            return success;
        }

        
        return fail;
    }
}