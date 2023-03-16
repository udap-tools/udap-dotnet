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
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Duende.IdentityServer.Models;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Util.Extensions;

namespace Udap.Server.Registration;

/// <summary>
/// UDAP or HL7 UDAP Validator?  TODO: finish this
/// </summary>
public class UdapDynamicClientRegistrationValidator : IUdapDynamicClientRegistrationValidator
{
    private readonly TrustChainValidator _trustChainValidator;
    private readonly ILogger _logger;
    private readonly ServerSettings _serverSettings;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UdapDynamicClientRegistrationValidator(
        TrustChainValidator trustChainValidator,
        ServerSettings serverSettings,
        IHttpContextAccessor httpContextAccessor,
        ILogger<UdapDynamicClientRegistrationValidator> logger)
    {
        _trustChainValidator = trustChainValidator;
        _serverSettings = serverSettings;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task<UdapDynamicClientRegistrationValidationResult> ValidateAsync(
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
            return Task.FromResult(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    UdapDynamicClientRegistrationErrorDescriptions.CannotFindorParseX5c));
        }

        var publicCert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
       
        var validatedToken = tokenHandler.ValidateToken(request.SoftwareStatement, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = new[]
                {
                    // Udap section 4.3 is strict concerning the SANs being of type uniformResourceIdentifier. https://www.udap.org/udap-dynamic-client-registration.html
                    // See RFC 2459 for SAN choice semantics https://www.rfc-editor.org/rfc/rfc2459#section-4.2.1.7
                    publicCert.GetNameInfo(X509NameType.UrlName, false)
                }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                ValidateAudience = false, // No aud for UDAP metadata
                ValidateLifetime = true,
                IssuerSigningKey = new X509SecurityKey(publicCert),
                ValidAlgorithms = new[] { jsonWebToken.Alg }, //must match signing algorithm
                // AudienceValidator = (audiences, token, parameters) =>  Potential enhanced validation.  or replace inline validation code below
            }
        );
        
        if (!validatedToken.IsValid)
        {
            if (validatedToken.Exception.GetType() == typeof(SecurityTokenNoExpirationException))
            {
                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    UdapDynamicClientRegistrationErrorDescriptions.ExpMissing));
            }

            if (validatedToken.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    $"{UdapDynamicClientRegistrationErrorDescriptions.ExpExpired}: {validatedToken.Exception.Message}"));
            }
            
            _logger.LogWarning(validatedToken.Exception, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.FailedTokenValidation));
        }

        var document = new UdapDynamicClientRegistrationDocument();
        document.AddClaims(jsonWebToken.Claims);

        if (document.Subject == null)
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing);

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing));
        }

        if (document.Subject != document.Issuer)
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss);
            
            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss));
        }

        if (!Uri.TryCreate(document.Audience, UriKind.Absolute, out var aud))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidAud}: {aud}");

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
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

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud}"));
        }

        

        //TODO Server Config for iat window (clock skew?)
        if (document.IssuedAt == 0)
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.IssuedAtMissing);

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
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

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.IssuedAtInFuture));
        }

        if (string.IsNullOrEmpty(document.ClientName))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing);

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing));
        }

        if (string.IsNullOrEmpty(document.TokenEndpointAuthMethod))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing);

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing));
        }

        //TODO Inject the client
        var client = new Duende.IdentityServer.Models.Client
        {
            //TODO: Maybe inject a component to generate the clientID so a user can use their own technique.
            ClientId = CryptoRandom.CreateUniqueId()
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

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate));
        }

        //////////////////////////////
        // validate grant types
        //////////////////////////////
        if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.ClientCredentials))
        {
            client.AllowedGrantTypes.Add(GrantType.ClientCredentials);
        }
        if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode))
        {
            client.AllowedGrantTypes.Add(GrantType.AuthorizationCode); 
        }

        // we only support the two above grant types
        if (client.AllowedGrantTypes.Count == 0)
        {
            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                "unsupported grant type"));
        }

        //TODO: Ensure test covers this and follows Security IG: http://hl7.org/fhir/us/udap-security/b2b.html#refresh-tokens
        if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.RefreshToken))
        {
            if (client.AllowedGrantTypes.Count == 1 &&
                client.AllowedGrantTypes.FirstOrDefault(t => t.Equals(GrantType.ClientCredentials)) != null)
            {
                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    "client credentials does not support refresh tokens"));
            }

            client.AllowOfflineAccess = true;
        }

        //
        // validate redirect URIs and ResponseTypes
        //
        if (client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
        {
            if (document.RedirectUris != null && document.RedirectUris.Any())
            {
                foreach (var requestRedirectUri in document.RedirectUris)
                {
                    //TODO add tests and decide how to handle invalid Uri exception
                    var uri = new Uri(requestRedirectUri);

                    if (uri.IsAbsoluteUri)
                    {
                        client.RedirectUris.Add(uri.AbsoluteUri);
                        //TODO: I need to create a policy engine or dig into the Duende policy stuff and see it if makes sense
                        //Threat analysis?
                        client.RequirePkce = false;
                        client.AllowOfflineAccess = true;
                    }
                    else
                    {
                        return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                            UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                            "malformed redirect URI"));
                    }
                }
            }
            else
            {
                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    "redirect URI required for authorization_code grant type"));
            }

            if (document.ResponseTypes != null && document.ResponseTypes.Count == 0)
            {
                _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                                   UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing);

                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing));
            }
        }



        if (client.AllowedGrantTypes.Count == 1 &&
            client.AllowedGrantTypes.FirstOrDefault(t => t.Equals(GrantType.ClientCredentials)) != null)
        {
            //TODO: find the RFC reference for this rule and add a Test
            if (document.RedirectUris != null && document.RedirectUris.Any())
            {
                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    "redirect URI not compatible with client_credentials grant type"));
            }
        }

        //////////////////////////////
        // validate scopes
        //////////////////////////////
        
        if (_serverSettings.ServerSupport == ServerSupport.Hl7SecurityIG && (document.Scope == null || !document.Scope.Any()))
        {
            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
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

                if (document.GrantTypes != null && document.GrantTypes.Contains(GrantType.ClientCredentials))
                {
                    scopes = _serverSettings.DefaultSystemScopes?.FromSpaceSeparatedString();
                }
                else if (document.GrantTypes != null && document.GrantTypes.Contains(GrantType.AuthorizationCode))
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
            string[] scopes = document.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            // todo: ideally scope names get checked against configuration store?
            
            foreach (var scope in scopes)
            {
                client?.AllowedScopes.Add(scope);
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
        return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(client, document));
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

    private readonly string[]? _x5cArray = null;

    private string[]? Getx5c(JwtHeader jwtHeader)
    {
        if (_x5cArray != null && _x5cArray.Any()) return _x5cArray;

        if (jwtHeader.X5c == null)
        {
            return null;
        }

        var x5cArray = JsonSerializer.Deserialize<string[]>(jwtHeader.X5c);
        
        if (x5cArray != null && !x5cArray.Any())
        {
            return null;
        }

        return x5cArray;
    }
}
