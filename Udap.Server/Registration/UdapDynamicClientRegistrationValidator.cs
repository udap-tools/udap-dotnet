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
using Microsoft.Extensions.Logging;
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

    public UdapDynamicClientRegistrationValidator(
        TrustChainValidator trustChainValidator,
        ServerSettings serverSettings,
        ILogger<UdapDynamicClientRegistrationValidator> logger)
    {
        _trustChainValidator = trustChainValidator;
        _serverSettings = serverSettings;
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
        var handler = new JwtSecurityTokenHandler();
        var jwtSecurityToken = handler.ReadToken(request.SoftwareStatement) as JwtSecurityToken;

        if (jwtSecurityToken == null)
        {
            _logger.LogError("No security token found");

            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(Constants.TokenErrors.MissingSecurityToken));
        }

        var document = new UdapDynamicClientRegistrationDocument();
        document.AddClaims(jwtSecurityToken.Claims);

        var client = new Duende.IdentityServer.Models.Client
        {
            //TODO: Maybe inject a componnet to generate the clientID so a user can use their own technique.
            ClientId = CryptoRandom.CreateUniqueId()
        };

        if (!ValidateChain(client, jwtSecurityToken, communityTrustAnchors, communityRoots))
        {
            _logger.LogWarning("Untrusted; Certificate is not a member of community");
            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult("Untrusted", "Certificate is not a member of community"));
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

        //////////////////////////////
        // validate redirect URIs
        //////////////////////////////
        if (client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
        {
            if (document.RedirectUris.Any())
            {
                foreach (var requestRedirectUri in document.RedirectUris)
                {
                    if (requestRedirectUri.IsAbsoluteUri)
                    {
                        client.RedirectUris.Add(requestRedirectUri.AbsoluteUri);
                    }
                    else
                    {
                        return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                            UdapDynamicClientRegistrationErrors.InvalidRedirectUri,
                            "malformed redirect URI"));
                    }
                }
            }
            else
            {
                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidRedirectUri,
                    "redirect URI required for authorization_code grant type"));
            }
        }



        if (client.AllowedGrantTypes.Count == 1 &&
            client.AllowedGrantTypes.FirstOrDefault(t => t.Equals(GrantType.ClientCredentials)) != null)
        {
            //TODO: find the RFC reference for this rule and add a Test
            if (document.RedirectUris.Any())
            {
                return Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidRedirectUri,
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
        JwtSecurityToken jwtSecurityToken,
        X509Certificate2Collection communityTrustAnchors,
        X509Certificate2Collection? rootCertificates)
    {
        var x5cArray = JsonSerializer.Deserialize<string[]>(jwtSecurityToken.Header.X5c);

        if (!x5cArray.Any())
        {
            throw new ArgumentNullException("JsonSerializer.Deserialize<string[]>(jwtSecurityToken.Header.X5c)");
        }

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

        _logger.LogInformation($"jwt payload {jwtSecurityToken.Payload}");
        _logger.LogInformation($"X5c {jwtSecurityToken.Header.X5c}");

        return false;
    }
}
