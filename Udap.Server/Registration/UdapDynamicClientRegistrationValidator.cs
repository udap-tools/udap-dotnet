#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

//
// Most of this file is copied from Duende's Identity Server dom/dcr-proc branch
// 
//

using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using Udap.Util.Extensions;
using static Udap.Model.UdapConstants;

namespace Udap.Server.Registration;

/// <summary>
/// UDAP or HL7 UDAP Validator?  TODO: finish this
/// </summary>
public class UdapDynamicClientRegistrationValidator : IUdapDynamicClientRegistrationValidator
{
    private readonly TrustChainValidator _trustChainValidator;
    private readonly IReplayCache _replayCache;
    private readonly ILogger _logger;
    private readonly ServerSettings _serverSettings;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IScopeExpander _scopeExpander;
    private readonly IResourceStore _resourceStore; 

    private const string Purpose = nameof(UdapDynamicClientRegistrationValidator);

    public UdapDynamicClientRegistrationValidator(
        TrustChainValidator trustChainValidator,
        IReplayCache replayCache,
        ServerSettings serverSettings,
        IHttpContextAccessor httpContextAccessor,
        IScopeExpander scopeExpander,
        IResourceStore resourceStore, //TODO use CachingResourceStore
        ILogger<UdapDynamicClientRegistrationValidator> logger)
    {
        _trustChainValidator = trustChainValidator;
        _replayCache = replayCache;
        _serverSettings = serverSettings;
        _httpContextAccessor = httpContextAccessor;
        _scopeExpander = scopeExpander;
        _resourceStore = resourceStore;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<UdapDynamicClientRegistrationValidationResult> ValidateAsync(
        UdapRegisterRequest request,
        X509Certificate2Collection? intermediateCertificates,
        X509Certificate2Collection anchorCertificates,
        IEnumerable<Anchor> anchors
        )
    {
        using var activity = Tracing.ValidationActivitySource.StartActivity("UdapDynamicClientRegistrationValidator.Validate");

        _logger.LogDebug($"Start client validation with Server Support Type {_serverSettings.ServerSupport}");


        var tokenHandler = new JsonWebTokenHandler();
        var jsonWebToken = tokenHandler.ReadJsonWebToken(request.SoftwareStatement);
        var jwtHeader = JwtHeader.Base64UrlDeserialize(jsonWebToken.EncodedHeader);
        
        var x5cArray = Getx5c(jwtHeader);

        if (x5cArray == null)
        {
            return await Task.FromResult(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    UdapDynamicClientRegistrationErrorDescriptions.CannotFindorParseX5c));
        }

        var publicCert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
        var subAltNames = publicCert.GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI);
        TokenValidationResult? validatedToken = null;
        var publicKey = publicCert?.PublicKey.GetRSAPublicKey();
        
        if (publicKey != null)
        {
            validatedToken = tokenHandler.ValidateToken(request.SoftwareStatement,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    // Udap section 4.3 is strict concerning the SANs being of type uniformResourceIdentifier. https://www.udap.org/udap-dynamic-client-registration.html
                    // See RFC 2459 for SAN choice semantics https://www.rfc-editor.org/rfc/rfc2459#section-4.2.1.7
                    ValidIssuers = subAltNames.Select(san => san.Item2).ToArray(),
                    //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                    ValidateAudience = false, // No aud for UDAP metadata
                    ValidateLifetime = true,
                    IssuerSigningKey = new X509SecurityKey(publicCert),
                    ValidAlgorithms = new[] { jsonWebToken.Alg }, //must match signing algorithm
                    // AudienceValidator = (audiences, token, parameters) =>  Potential enhanced validation.  or replace inline validation code below
                }
            );
        }
        else
        {
            var ecdsaPublicKey = publicCert?.PublicKey.GetECDsaPublicKey();

            validatedToken = tokenHandler.ValidateToken(request.SoftwareStatement,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuers = subAltNames.Select(san => san.Item2).ToArray(),
                    ValidateAudience = false, // No aud for UDAP metadata
                    ValidateLifetime = true,
                    IssuerSigningKey = new ECDsaSecurityKey(ecdsaPublicKey),
                    ValidAlgorithms = new[] { jsonWebToken.Alg }, //must match signing algorithm
                });
        }

        if (!validatedToken.IsValid)
        {
            if (validatedToken.Exception.GetType() == typeof(SecurityTokenNoExpirationException))
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    UdapDynamicClientRegistrationErrorDescriptions.ExpMissing));
            }

            if (validatedToken.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    $"{UdapDynamicClientRegistrationErrorDescriptions.ExpExpired}: {validatedToken.Exception.Message}"));
            }
            
            _logger.LogWarning(validatedToken.Exception, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.FailedTokenValidation));
        }

        var document = new UdapDynamicClientRegistrationDocument();
        document.AddClaims(jsonWebToken.Claims);

        if (_serverSettings.RegistrationJtiRequired)
        {
            var result = await ValidateJti(document, jsonWebToken.ValidTo);

            if (result.IsError)
            {
                return result;
            }
        }



        if (document.Subject == null)
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing));
        }

        if (document.Subject != document.Issuer)
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss);
            
            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss));
        }

        if (!Uri.TryCreate(document.Audience, UriKind.Absolute, out var aud))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidAud}: {aud}");

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidAud}: {aud}"));
        }


        var endpoint = new Uri(_httpContextAccessor.HttpContext!.Request.GetDisplayUrl());

        if (Uri.Compare(endpoint, aud,
                UriComponents.Host | UriComponents.PathAndQuery | UriComponents.Port,
                UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase)
            != 0)
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud}");

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud}"));
        }

        

        //TODO Server Config for iat window (clock skew?)
        if (document.IssuedAt == 0)
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.IssuedAtMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.IssuedAtMissing));
        }

        var iat = EpochTime.DateTime(document.IssuedAt).ToUniversalTime();
        var exp = EpochTime.DateTime(document.Expiration).ToUniversalTime();
        //TODO Server Config for iat window (clock skew?)
        if (iat > DateTime.UtcNow.AddSeconds(5))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.IssuedAtInFuture);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.IssuedAtInFuture));
        }

        if (string.IsNullOrEmpty(document.ClientName))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing));
        }

        if (string.IsNullOrEmpty(document.TokenEndpointAuthMethod))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing));
        }

        //TODO There should be a context already created where the client can be injected.
        var client = new Duende.IdentityServer.Models.Client
        {
            //TODO: Maybe inject a component to generate the clientID so a user can use their own technique.
            ClientId = CryptoRandom.CreateUniqueId(),
            AlwaysIncludeUserClaimsInIdToken = _serverSettings.AlwaysIncludeUserClaimsInIdToken
        };

        
        if (!ValidateChain(client, jsonWebToken, jwtHeader, intermediateCertificates, anchorCertificates, anchors))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate);

            var sb = new StringBuilder();
            sb.AppendLine($"Client Thumbprint: {publicCert.Thumbprint}");
            
            if (intermediateCertificates != null)
            {
                sb.AppendLine(
                    $"Intermediate Thumbprints: {string.Join(" | ", intermediateCertificates.Select(a => a.Thumbprint))}");

            }

            sb.AppendLine($"Anchor Certificate Thumbprints: {string.Join(" | ", anchorCertificates.Select(a => a.Thumbprint))}");
            _logger.LogWarning(sb.ToString());

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate));
        }

        //////////////////////////////
        // validate grant_types
        //////////////////////////////
        if (jsonWebToken.Claims.FirstOrDefault(c => c.Type == RegistrationDocumentValues.GrantTypes) == null)
        {
            //
            // The jsonWeToken.Claims will always drop an empty array.  So we can not tell the difference
            // between a Cancel Registration (empty array of grant_types) vs an invalid_client_metadata error.
            // So in this path we look at the payload for the grant_types string.
            //
            var payload = Base64UrlEncoder.Decode(jsonWebToken.EncodedPayload);
            
            if (payload != null)
            {
                if (!payload.Contains(RegistrationDocumentValues.GrantTypes))
                {
                    _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                                       UdapDynamicClientRegistrationErrorDescriptions.GrantTypeMissing);

                    return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                        UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                        UdapDynamicClientRegistrationErrorDescriptions.GrantTypeMissing));
                }
            }
        }
        
        
        if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.ClientCredentials))
        {
            client.AllowedGrantTypes.Add(OidcConstants.GrantTypes.ClientCredentials);
        }
        if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode))
        {
            client.AllowedGrantTypes.Add(OidcConstants.GrantTypes.AuthorizationCode); 
        }

        // we only support the two above grant types but, an empty GrantType is an indication of a cancel registration action.
        // TODO: This whole method needs to be migrated into a better software pattern.  Also, UdapTieredOAuthMiddleware now has this logic
        if (client.AllowedGrantTypes.Count == 0 && 
            document.GrantTypes != null && 
            document.GrantTypes.Any())
        {
            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.UnsupportedGrantType));
        }

        //TODO: Ensure test covers this and follows Security IG: http://hl7.org/fhir/us/udap-security/b2b.html#refresh-tokens
        if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.RefreshToken))
        {
            if (client.AllowedGrantTypes.Count == 1 &&
                client.AllowedGrantTypes.FirstOrDefault(t => t.Equals(OidcConstants.GrantTypes.ClientCredentials)) != null)
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.ClientCredentialsRefreshError));
            }

            client.AllowOfflineAccess = true;
        }

        //
        // validate redirect URIs and ResponseTypes and logo_uri
        //
        if (client.AllowedGrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode))
        {
            if (_serverSettings.LogoRequired)
            {
                if ( ! ValidateLogoUri(document, out UdapDynamicClientRegistrationValidationResult? errorResult))
                {
                    return errorResult!;
                }

                client.LogoUri = document.LogoUri;
            }

            if (document.RedirectUris != null && document.RedirectUris.Any())
            {
                foreach (var requestRedirectUri in document.RedirectUris)
                {
                    //TODO add tests and decide how to handle invalid Uri exception
                    var uri = new Uri(requestRedirectUri);

                    if (uri.IsAbsoluteUri)
                    {
                        client.RedirectUris.Add(uri.OriginalString);
                        //TODO: I need to create a policy engine or dig into the Duende policy stuff and see it if makes sense
                        client.RequirePkce = false;
                    }
                    else
                    {
                        return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                            UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                            UdapDynamicClientRegistrationErrorDescriptions.MalformedRedirectUri));
                    }
                }
            }
            else
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.RedirectUriRequiredForAuthCode));
            }

            if (document.ResponseTypes != null && document.ResponseTypes.Count == 0)
            {
                _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                                   UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing);

                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing));
            }
        }

        if (client.AllowedGrantTypes.Count == 1 &&
            client.AllowedGrantTypes.FirstOrDefault(t => t.Equals(OidcConstants.GrantTypes.ClientCredentials)) != null)
        {
            //TODO: find the RFC reference for this rule and add a Test
            if (document.RedirectUris != null && document.RedirectUris.Any())
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    "redirect URI not compatible with client_credentials grant type"));
            }
        }

        //////////////////////////////
        // validate scopes
        //////////////////////////////
        
        if (client.AllowedGrantTypes.Count != 0 && //Cancel Registration
            _serverSettings.ServerSupport == ServerSupport.Hl7SecurityIG && 
            (document.Scope == null || !document.Scope.Any()))
        {
            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                "scope is required"));
        }

        // Enrich Scopes:  Todo: inject a ScopeEnricher
        
        // TODO: Need a policy engine for various things.  UDAP ServerMode allows and empty scope during registration.
        // So some kind of policy linked to maybe issued certificate certification and/or community or something
        // There are a lot of choices left up to a community.  The HL7 ServerMode requires scopes to be sent during registration.
        // This doesn't mean the problem is easier it just means  we could filter down during registration even if policy
        // allowed for a broader list of scopes.
        // Below I use ServerSettings from appsettings.  This basically says that server is either UDAP or HL7 mode.  Well
        // sort of.  The code is only trying to pass udap.org tests and survive a HL7 connect-a-thon. By putting the logic in
        // a policy engine we can have one server UDAP and Hl7 Mode or whatever the policy engine allows.  

        //
        // Also there should be a better way to do this.  It will repeat many scope entries per client.
        //
        if (_serverSettings.ServerSupport == ServerSupport.UDAP)
        {
            if (string.IsNullOrWhiteSpace(document.Scope))
            {
                IEnumerable<string>? scopes = null;

                if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.ClientCredentials))
                {
                    scopes = _serverSettings.DefaultSystemScopes?.FromSpaceSeparatedString();
                }
                else if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode))
                {
                    scopes = _serverSettings.DefaultUserScopes?.FromSpaceSeparatedString();
                }

                if (scopes != null)
                {
                    foreach (var scope in scopes)
                    {
                        client?.AllowedScopes.Add(scope);
                    }
                }
            }
        }
        if (document.Scope != null && document.Any())
        {
            var scopes = document.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            // todo: ideally scope names get checked against configuration store?

            var resources = await _resourceStore.GetAllEnabledResourcesAsync();
            var expandedScopes = _scopeExpander.Expand(scopes).ToList();
            var explodedScopes = _scopeExpander.WildCardExpand(expandedScopes, resources.ApiScopes.Select(a => a.Name).ToList()).ToList();
            var allowedApiScopes = resources.ApiScopes.Where(s => explodedScopes.Contains(s.Name));
            
            foreach (var scope in allowedApiScopes)
            {
                client?.AllowedScopes.Add(scope.Name);
            }
            
            var allowedResourceScopes = resources.IdentityResources.Where(s => explodedScopes.Contains(s.Name));

            foreach (var scope in allowedResourceScopes.Where(s => s.Enabled).Select(s => s.Name))
            {
                client?.AllowedScopes.Add(scope);
            }

            //
            // Present scopes in aggregate form
            //
            if (client?.AllowedScopes != null)
            {
                document.Scope = _scopeExpander.Aggregate(client.AllowedScopes).OrderBy(s => s).ToSpaceSeparatedString();
            }
        }


        if (!string.IsNullOrWhiteSpace(document.ClientName))
        {
            if (client != null)
            {
                client.ClientName = document.ClientName;
            }
        }

        // validation successful - return client
        return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(client, document));
    }

    public bool ValidateLogoUri(UdapDynamicClientRegistrationDocument document,
        out UdapDynamicClientRegistrationValidationResult? errorResult)
    {
        errorResult = null;

        if (string.IsNullOrEmpty(document.LogoUri))
        {
            errorResult = new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.LogoMissing);

            return false;
        }

        if (Uri.TryCreate(document.LogoUri, UriKind.Absolute, out var logoUri))
        {
            if (!logoUri.OriginalString.EndsWith("png", StringComparison.OrdinalIgnoreCase) &&
                !logoUri.OriginalString.EndsWith("jpg", StringComparison.OrdinalIgnoreCase) &&
                !logoUri.OriginalString.EndsWith("gif", StringComparison.OrdinalIgnoreCase))
            {
                errorResult = new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidFileType);

                return false;
            }

            if (!logoUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                errorResult = new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidScheme);

                return false;
            }

           
        }
        else
        {
            errorResult = new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidUri);

            return false;
        }

        return true;
    }

    public async Task<UdapDynamicClientRegistrationValidationResult> ValidateJti(
        UdapDynamicClientRegistrationDocument document,
        DateTime validTo)
    {
        var jti = document.JwtId;
        

        if (jti == null || jti.IsMissing())
        {
            _logger.LogWarning("jti is missing.");
            return new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.InvalidJti);
            
        }

        if (await _replayCache.ExistsAsync(Purpose, jti))
        {
            _logger.LogWarning("jti is found in replay cache. Possible replay attack.");

            return new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.Replay);
        }
        else
        {
            await _replayCache.AddAsync(Purpose, jti, validTo.AddMinutes(5));
        }


        return new UdapDynamicClientRegistrationValidationResult(string.Empty);
    }

    private bool ValidateChain(
        Duende.IdentityServer.Models.Client client,
        JsonWebToken jwtSecurityToken,
        JwtHeader jwtHeader,
        X509Certificate2Collection? intermediateCertificates,
        X509Certificate2Collection anchorCertificates,
        IEnumerable<Anchor> anchors)
    {
        var x5cArray = Getx5c(jwtHeader);
        
        
        // TODO: no test cases for x5c with intermediate certificates.  
        if (x5cArray != null)
        {
            var cert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));

            if (_trustChainValidator.IsTrustedCertificate(
                    client.ClientName, //TODO: clientName is not set?
                    cert,
                    intermediateCertificates,
                    anchorCertificates, 
                    out X509ChainElementCollection? chainElements,
                    out long? communityId,
                    anchors))
            {
                if (chainElements == null)
                {
                    _logger.LogError("Missing chain elements");

                    return false;
                }

               var clientSecrets = client.ClientSecrets = new List<Secret>();

               clientSecrets.Add(new()
                {
                    Expiration = chainElements.First().Certificate.NotAfter,
                    Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME,
                    Value = jwtSecurityToken.Issuer
                });

                clientSecrets.Add(new()
                {
                    Expiration = chainElements.First().Certificate.NotAfter,
                    Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY,
                    Value = communityId.ToString()
                });

                return true;
            }
        }

        _logger.LogDebug($"jwt payload {jwtSecurityToken.EncodedPayload}");
        _logger.LogDebug($"x5c { jwtHeader.X5c }");

        return false;
    }

    private string[]? _x5cArray = null;

    //Todo duplicate code
    private string[]? Getx5c(JwtHeader jwtHeader)
    {
        if (_x5cArray != null && _x5cArray.Any()) return _x5cArray;

        if (jwtHeader.X5c == null)
        {
            return null;
        }

        var certificates = jwtHeader["x5c"] as List<object>;

        if (certificates == null)
        {
            return null;
        }

        _x5cArray = certificates.Select(c => c.ToString()).ToArray()!;
        
        return _x5cArray;
    }
}
