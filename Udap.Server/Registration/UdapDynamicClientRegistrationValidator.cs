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
using System.Text.Json;
using Duende.IdentityServer.Models;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Messages;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Registration;
using Udap.Server.Configuration;

namespace Udap.Server.Registration;

/// <summary>
/// UDAP or HL7 UDAP Validator?  TODO: finish this
/// </summary>
public class UdapDynamicClientRegistrationValidator : IUdapDynamicClientRegistrationValidator
{
    private TrustChainValidator _trustChainValidator;
    private readonly ILogger _logger;
    private readonly ServerSettings _serverSettings;
    private IHttpContextAccessor _httpContextAccessor;

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
        X509Certificate2Collection communityTrustAnchors,
        X509Certificate2Collection? communityRoots = null
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
            

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                "Failed JsonWebTokenHandler.ValidateToken"));
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

        var client = new Duende.IdentityServer.Models.Client
        {
            //TODO: Maybe inject a componnet to generate the clientID so a user can use their own technique.
            ClientId = CryptoRandom.CreateUniqueId()
        };

        
        if (!ValidateChain(client, jsonWebToken, jwtHeader, communityTrustAnchors, communityRoots))
        {
            _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement}::" +
                               UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate);

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate));
        }

        //////////////////////////////
        // validate grant types
        //////////////////////////////
        if (document.GrantTypes.Contains(OidcConstants.GrantTypes.ClientCredentials))
        {
            client.AllowedGrantTypes.Add(GrantType.ClientCredentials);
        }
        if (document.GrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode))
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
        if (document.GrantTypes.Contains(OidcConstants.GrantTypes.RefreshToken))
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
            if (document.RedirectUris.Any())
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

            if (document.ResponseTypes.Count == 0)
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
            if (document.RedirectUris.Any())
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

        if (document.Scope != null && document.Any())
        {
            var scopes = document.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            // todo: ideally scope names get checked against configuration store?

            foreach (var scope in scopes)
            {
                client.AllowedScopes.Add(scope);
            }
        }


        if (!string.IsNullOrWhiteSpace(document.ClientName))
        {
            client.ClientName = document.ClientName;
        }

        // validation successful - return client
        return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(client, document));
    }

    private bool ValidateChain(
        Duende.IdentityServer.Models.Client client,
        JsonWebToken jwtSecurityToken,
        JwtHeader jwtHeader,
        X509Certificate2Collection communityTrustAnchors,
        X509Certificate2Collection? rootCertificates)
    {
        var x5cArray = Getx5c(jwtHeader);

        // TODO: no test cases for x5c with intermediate certificates.  
        var cert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));

        if (_trustChainValidator.IsTrustedCertificate(
                client.ClientName,
                cert,
                communityTrustAnchors,
                out X509ChainElementCollection? chainElements,
                rootCertificates))
        {
            if (chainElements == null)
            {
                _logger.LogError("Missing chain elements");

                return false;
            }

            var clientSecrets = client.ClientSecrets = new List<Secret>();

            foreach (var chainElement in chainElements.Skip(1))
            {
                clientSecrets.Add(new()
                {
                    Expiration = chainElements.First().Certificate.NotAfter,
                    Type = UdapServerConstants.SecretTypes.Udap_X509_Pem,
                    Value = Convert.ToBase64String(chainElement.Certificate.Export(X509ContentType.Cert))
                });
            }

            return true;
        }

        //TODO: do I want this logged?
        _logger.LogInformation($"jwt payload {jwtSecurityToken.EncodedPayload}");
        _logger.LogInformation($"X5c {jwtHeader}");

        return false;
    }

    private string[]? _x5cArray = null;

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
