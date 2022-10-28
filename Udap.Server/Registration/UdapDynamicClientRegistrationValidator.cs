#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer.Models;
using IdentityModel;
using Udap.Common.Certificates;

namespace Udap.Server.Registration;

/// <summary>
/// UDAP or HL7 UDAP Validator?  TODO: finish this
/// </summary>
public class UdapDynamicClientRegistrationValidator : IUdapDynamicClientRegistrationValidator
{
    private TrustChainValidator _trustChainValidator;
    

    public UdapDynamicClientRegistrationValidator(TrustChainValidator trustChainValidator)
    {
        _trustChainValidator = trustChainValidator;

    }
    /// <inheritdoc />
    public Task<UdapDynamicClientRegistrationValidationResult> ValidateAsync(
        UdapRegisterRequest request, 
        X509Certificate2Collection communityTrustAnchors,
        X509Certificate2Collection? communityRoots = null
        )
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtSecurityToken = handler.ReadToken(request.SoftwareStatement) as JwtSecurityToken;

        var document = new UdapDynamicClientRegistrationDocument();
        document.AddClaims(jwtSecurityToken.Claims);
        
        if (!ValidateChain(jwtSecurityToken, communityTrustAnchors, communityRoots))
        {
            return Task.FromResult(new UdapDynamicClientRegistrationValidationResult("Untrusted", "Certificate is not a member of community"));
        }
        
        var client = new Duende.IdentityServer.Models.Client
        {
            //TODO: Maybe inject a componnet to generate the clientID so a user can use their own technique.
            ClientId = CryptoRandom.CreateUniqueId()
        };
        
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
        if (string.IsNullOrEmpty(document.Scope))
        {
            // todo: what to do when scopes are missing? error - leave up to custom validator?
        }
        else
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
        JwtSecurityToken jwtSecurityToken, 
        X509Certificate2Collection communityTrustAnchors, 
        X509Certificate2Collection? rootCertificates)
    {
        var x5cArray = JsonSerializer.Deserialize<string[]>(jwtSecurityToken.Header.X5c) ;

        if (!x5cArray.Any())
        {
            throw new ArgumentNullException("JsonSerializer.Deserialize<string[]>(jwtSecurityToken.Header.X5c)");
        }

        X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
        
        return _trustChainValidator.IsTrustedCertificate(cert, communityTrustAnchors, rootCertificates);
    }
}