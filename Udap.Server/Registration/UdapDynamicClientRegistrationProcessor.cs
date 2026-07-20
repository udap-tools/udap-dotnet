#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Duende.IdentityModel;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.Logging;
using Udap.Server.Configuration;
using Udap.Server.Storage;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Registration;

/// <summary>
/// Creates and persists a <see cref="Client"/> from a validated UDAP registration context.
/// </summary>
public class UdapDynamicClientRegistrationProcessor : IUdapDynamicClientRegistrationProcessor
{
    private readonly IUdapClientRegistrationStore _store;
    private readonly ServerSettings _serverSettings;
    private readonly ILogger<UdapDynamicClientRegistrationProcessor> _logger;

    public UdapDynamicClientRegistrationProcessor(
        IUdapClientRegistrationStore store,
        ServerSettings serverSettings,
        ILogger<UdapDynamicClientRegistrationProcessor> logger)
    {
        _store = store;
        _serverSettings = serverSettings;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<UdapDynamicClientRegistrationProcessorResult> ProcessAsync(
        UdapDynamicClientRegistrationContext context,
        CancellationToken cancellationToken = default)
    {
        var document = context.Document!;

        // Build the client
        var client = new Duende.IdentityServer.Models.Client
        {
            ClientId = CryptoRandom.CreateUniqueId(),
            AlwaysIncludeUserClaimsInIdToken = _serverSettings.AlwaysIncludeUserClaimsInIdToken,
            RequireConsent = _serverSettings.RequireConsent,
            AllowRememberConsent = _serverSettings.AllowRememberConsent,
            RequirePkce = _serverSettings.EffectiveRequirePkce,
            RequireDPoP = _serverSettings.ForceDPoP || (document.DPoPEnabled == true)
        };

        // Organization / DataHolder properties
        if (!string.IsNullOrWhiteSpace(context.Organization) && !string.IsNullOrWhiteSpace(context.DataHolder))
        {
            client.Properties[UdapServerConstants.ClientPropertyConstants.Organization] = context.Organization;
            client.Properties[UdapServerConstants.ClientPropertyConstants.DataHolder] = context.DataHolder;
        }
        else
        {
            client.Properties[UdapServerConstants.ClientPropertyConstants.Organization] = UdapServerConstants.ClientPropertyConstants.DefaultOrgMap;
            client.Properties[UdapServerConstants.ClientPropertyConstants.DataHolder] = UdapServerConstants.ClientPropertyConstants.DefaultOrgMap;
        }

        // Community name property (feature-flagged). The udap_community access-token claim is
        // resolved from the community id at token time; this property surfaces the name for display.
        if (_serverSettings.IncludeCommunityClaim && !string.IsNullOrWhiteSpace(context.CommunityName))
        {
            client.Properties[UdapServerConstants.ClientPropertyConstants.Community] = context.CommunityName;
        }

        // Client secrets from certificate chain
        var clientSecrets = client.ClientSecrets = new List<Secret>();

        if (context.Issuer != null && context.CertificateExpiration.HasValue)
        {
            clientSecrets.Add(new Secret
            {
                Expiration = context.CertificateExpiration.Value,
                Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME,
                Value = context.Issuer
            });
        }

        if (context.CommunityId.HasValue)
        {
            clientSecrets.Add(new Secret
            {
                Expiration = context.CertificateExpiration ?? DateTime.UtcNow,
                Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY,
                Value = context.CommunityId.Value.ToString()
            });
        }

        if (context.ClientCertificate != null)
        {
            clientSecrets.Add(new Secret
            {
                Type = UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE,
                Value = Convert.ToBase64String(context.ClientCertificate.Export(X509ContentType.Cert)),
                Expiration = context.CertificateExpiration
            });
        }

        // Grant types
        if (document.GrantTypes != null)
        {
            if (document.GrantTypes.Contains(OidcConstants.GrantTypes.ClientCredentials))
            {
                client.AllowedGrantTypes.Add(OidcConstants.GrantTypes.ClientCredentials);
            }

            if (document.GrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode))
            {
                client.AllowedGrantTypes.Add(OidcConstants.GrantTypes.AuthorizationCode);
            }

            if (document.GrantTypes.Contains(OidcConstants.GrantTypes.RefreshToken))
            {
                client.AllowOfflineAccess = true;
            }
        }

        // Cancel registration (empty grant types)
        if (client.AllowedGrantTypes.Count == 0)
        {
            var numberOfClientsRemoved = await _store.CancelRegistration(client, cancellationToken);
            client.ClientId = "removed";
            context.Client = client;

            if (numberOfClientsRemoved == 0)
            {
                return UdapDynamicClientRegistrationProcessorResult.CancellationFailed();
            }

            return UdapDynamicClientRegistrationProcessorResult.Cancelled();
        }

        // Authorization code specifics
        if (client.AllowedGrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode))
        {
            client.LogoUri = document.LogoUri;

            if (document.RedirectUris != null)
            {
                foreach (var redirectUri in document.RedirectUris)
                {
                    var uri = new Uri(redirectUri);
                    if (uri.IsAbsoluteUri)
                    {
                        client.RedirectUris.Add(uri.OriginalString);
                    }
                }
            }
        }

        // Scopes (already validated and expanded by the validator, stored in document.Scope)
        if (!string.IsNullOrWhiteSpace(document.Scope))
        {
            // The validator already expanded and aggregated the scopes back into document.Scope.
            // We need the individual expanded scope names for AllowedScopes.
            // Re-use the Items bag if the validator stored the resolved scope names there.
            if (context.Items.TryGetValue("ResolvedScopes", out var resolvedObj) && resolvedObj is IEnumerable<string> resolvedScopes)
            {
                foreach (var scope in resolvedScopes)
                {
                    client.AllowedScopes.Add(scope);
                }
            }
        }

        // Client name
        if (!string.IsNullOrWhiteSpace(document.ClientName))
        {
            client.ClientName = document.ClientName;
        }

        context.Client = client;

        _logger.LogDebug(
            "Processing registration: ClientId={ClientId}, RequirePkce={RequirePkce}, RequireDPoP={RequireDPoP}",
            client.ClientId, client.RequirePkce, client.RequireDPoP);

        // Persist
        var upsertFlag = await _store.UpsertClient(client, cancellationToken);

        _logger.LogInformation(
            upsertFlag ? "Updated client: {ClientId}" : "Created client: {ClientId}",
            client.ClientId);

        return UdapDynamicClientRegistrationProcessorResult.Success(upsertFlag);
    }
}
