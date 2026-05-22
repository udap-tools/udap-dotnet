#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// UdapModel is modeled after IdentityModel. See https://github.com/IdentityModel/IdentityModel
// 
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Text.Json;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.Jwk;
using Udap.Common.Extensions;
using Udap.Model;

namespace Udap.Client.Messages;


/// <summary>
/// Models the response from an UDAP discovery endpoint
/// </summary>
public class UdapDiscoveryDocumentResponse : ProtocolResponse
{
    /// <summary>
    /// Gets or sets the discovery policy used to validate the metadata endpoints.
    /// </summary>
    public DiscoveryPolicy? Policy { get; set; }

    protected override Task InitializeAsync(object? initializationData = null)
    {
        if (HttpResponse == null || !HttpResponse.IsSuccessStatusCode)
        {
            ErrorMessage = initializationData as string;
            return Task.CompletedTask;
        }

        Policy = initializationData as DiscoveryPolicy ?? new DiscoveryPolicy();

        var validationError = Validate(Policy);

        if (validationError.IsPresent())
        {
            Json = default;

            ErrorType = ResponseErrorType.PolicyViolation;
            ErrorMessage = validationError;
        }
        
        return Task.CompletedTask;
    }

    /// <summary>
    /// Gets the signed JWT containing the UDAP server metadata, as defined by the UDAP discovery profile.
    /// </summary>
    public string? SignedMetadata => TryGetString(UdapConstants.Discovery.SignedMetadata);

    /// <summary>
    /// Gets or sets the JSON web key set.
    /// </summary>
    /// <value>
    /// The key set.
    /// </value>
    public JsonWebKeySet? KeySet { get; set; }

    /// <summary>
    /// Gets the UDAP versions supported by the server (e.g., "1").
    /// </summary>
    public IEnumerable<string>? UdapVersionsSupported => TryGetStringArray(UdapConstants.Discovery.UdapVersionsSupported);

    /// <summary>
    /// Gets the UDAP profiles supported by the server (e.g., "udap_dcr", "udap_authn", "udap_authz").
    /// </summary>
    public IEnumerable<string>? UdapProfilesSupported => TryGetStringArray(UdapConstants.Discovery.UdapProfilesSupported);

    /// <summary>
    /// Gets the authorization extension objects supported by the server (e.g., "hl7-b2b", "acme-ext").
    /// </summary>
    public IEnumerable<string>? UdapAuthorizationExtensionsSupported => TryGetStringArray(UdapConstants.Discovery.UdapAuthorizationExtensionsSupported);

    /// <summary>
    /// Gets the authorization extension objects required by the server in token requests.
    /// </summary>
    public IEnumerable<string>? UdapAuthorizationExtensionsRequired => TryGetStringArray(UdapConstants.Discovery.UdapAuthorizationExtensionsRequired);

    /// <summary>
    /// Gets the certification URIs supported by the server for client certifications during registration.
    /// </summary>
    public IEnumerable<string>? UdapCertificationsSupported => TryGetStringArray(UdapConstants.Discovery.UdapCertificationsSupported);

    /// <summary>
    /// Gets the certification URIs required by the server during dynamic client registration.
    /// </summary>
    public IEnumerable<string>? UdapCertificationsRequired => TryGetStringArray(UdapConstants.Discovery.UdapCertificationsRequired);

    /// <summary>
    /// Gets the OAuth 2.0 grant types supported by the server (e.g., "authorization_code", "client_credentials").
    /// </summary>
    public IEnumerable<string>? GrantTypesSupported => TryGetStringArray(UdapConstants.Discovery.GrantTypesSupported);

    /// <summary>
    /// Gets the scopes supported by the server.
    /// </summary>
    public IEnumerable<string>? ScopesSupported => TryGetStringArray(UdapConstants.Discovery.ScopesSupported);

    /// <summary>
    /// Gets the token endpoint authentication methods supported by the server (e.g., "private_key_jwt").
    /// </summary>
    public IEnumerable<string>? TokenEndpointAuthMethodsSupported => TryGetStringArray(UdapConstants.Discovery.TokenEndpointAuthMethodsSupported);

    /// <summary>
    /// Gets the signing algorithms supported for token endpoint client authentication JWTs (e.g., "RS256", "ES384").
    /// </summary>
    public IEnumerable<string>? TokenEndpointAuthSigningAlgValuesSupported => TryGetStringArray(UdapConstants.Discovery.TokenEndpointAuthSigningAlgValuesSupported);

    /// <summary>
    /// Gets the signing algorithms supported for software statement JWTs submitted to the registration endpoint.
    /// </summary>
    public IEnumerable<string>? RegistrationEndpointJwtSigningAlgValuesSupported => TryGetStringArray(UdapConstants.Discovery.RegistrationEndpointJwtSigningAlgValuesSupported);

    /// <summary>
    /// Gets the URL of the server's JSON Web Key Set document.
    /// </summary>
    public string? JwksUri => TryGetString(UdapConstants.Discovery.JwksUri);

    /// <summary>
    /// Gets the authorization endpoint URL used to initiate the authorization code flow.
    /// </summary>
    public string? AuthorizeEndpoint => TryGetString(UdapConstants.Discovery.AuthorizationEndpoint);

    /// <summary>
    /// Gets the FHIR Authorization Server's token endpoint URL.
    /// </summary>
    public string? TokenEndpoint => TryGetString(UdapConstants.Discovery.TokenEndpoint);

    /// <summary>
    /// Gets the UDAP dynamic client registration endpoint URL.
    /// </summary>
    public string? RegistrationEndpoint => TryGetString(UdapConstants.Discovery.RegistrationEndpoint);

    // generic
    private string? TryGetString(string name) => Json?.TryGetString(name);
    private IEnumerable<string>? TryGetStringArray(string name) => Json?.TryGetStringArray(name);

    private string Validate(DiscoveryPolicy policy)
    {
        if (Json.HasValue)
        {
            var error = ValidateEndpoints(Json.Value, policy);
            if (error.IsPresent())
            {
                return error;
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Validates the endpoints and jwks_uri according to the security policy.
    /// </summary>
    /// <param name="json">The json.</param>
    /// <param name="policy">The policy.</param>
    /// <returns></returns>
    public static string ValidateEndpoints(JsonElement json, DiscoveryPolicy policy)
    {
        // allowed hosts
        var allowedHosts = new HashSet<string>(policy.AdditionalEndpointBaseAddresses.Select(e => new Uri(e).Authority))
        {
            new Uri(policy.Authority).Authority
        };

        // allowed authorities (hosts + base address)
        var allowedAuthorities = new HashSet<string>(policy.AdditionalEndpointBaseAddresses)
        {
            policy.Authority
        };

        foreach (var element in json.EnumerateObject())
        {
            if (element.Name.EndsWith("endpoint", StringComparison.OrdinalIgnoreCase) ||
                element.Name.Equals(UdapConstants.Discovery.JwksUri, StringComparison.OrdinalIgnoreCase) ||
                element.Name.Equals(OidcConstants.Discovery.CheckSessionIframe, StringComparison.OrdinalIgnoreCase))
            {
                var endpoint = element.Value.ToString();

                var isValidUri = Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri);

                if (!isValidUri || uri == null)
                {
                    return $"Malformed endpoint: {endpoint}";
                }

                if (!DiscoveryEndpoint.IsValidScheme(uri))
                {
                    return $"Malformed endpoint: {endpoint}";
                }

                if (!DiscoveryEndpoint.IsSecureScheme(uri, policy))
                {
                    return $"Endpoint does not use HTTPS: {endpoint}";
                }

                if (policy.ValidateEndpoints)
                {
                    // if endpoint is on exclude list, don't validate
                    if (policy.EndpointValidationExcludeList.Contains(element.Name))
                    {
                        continue;
                    }

                    bool isAllowed = false;
                    foreach (var host in allowedHosts)
                    {
                        if (string.Equals(host, uri.Authority))
                        {
                            isAllowed = true;
                        }
                    }

                    if (!isAllowed)
                    {
                        return $"Endpoint is on a different host than authority: {endpoint}";
                    }

                    var strategy = policy.AuthorityValidationStrategy ?? DiscoveryPolicy.DefaultAuthorityValidationStrategy;
                    var endpointValidationResult = strategy.IsEndpointValid(endpoint, allowedAuthorities);
                    if (!endpointValidationResult.Success)
                    {
                        return endpointValidationResult.ErrorMessage;
                    }
                }
            }
        }
        
        return string.Empty;
    }
}