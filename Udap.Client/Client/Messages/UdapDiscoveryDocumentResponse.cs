﻿#region (c) 2022 Joseph Shook. All rights reserved.
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
using IdentityModel;
using IdentityModel.Client;
using IdentityModel.Jwk;
using Udap.Common.Extensions;
using Udap.Model;

namespace Udap.Client.Client.Messages;


/// <summary>
/// Models the response from an UDAP discovery endpoint
/// </summary>
public class UdapDiscoveryDocumentResponse : ProtocolResponse
{
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

    public string? SignedMetadata => TryGetString(UdapConstants.Discovery.SignedMetadata);

    /// <summary>
    /// Gets or sets the JSON web key set.
    /// </summary>
    /// <value>
    /// The key set.
    /// </value>
    public JsonWebKeySet? KeySet { get; set; }

    // strongly typed
    public IEnumerable<string>? UdapVersionsSupported => TryGetStringArray(UdapConstants.Discovery.UdapVersionsSupported);
    public IEnumerable<string>? UdapProfilesSupported => TryGetStringArray(UdapConstants.Discovery.UdapProfilesSupported);
    public IEnumerable<string>? UdapAuthorizationExtensionsSupported => TryGetStringArray(UdapConstants.Discovery.UdapAuthorizationExtensionsSupported);
    public IEnumerable<string>? UdapAuthorizationExtensionsRequired => TryGetStringArray(UdapConstants.Discovery.UdapAuthorizationExtensionsRequired);
    public IEnumerable<string>? UdapCertificationsSupported => TryGetStringArray(UdapConstants.Discovery.UdapCertificationsSupported);
    public IEnumerable<string>? UdapCertificationsRequired => TryGetStringArray(UdapConstants.Discovery.UdapCertificationsRequired);
    public IEnumerable<string>? GrantTypesSupported => TryGetStringArray(UdapConstants.Discovery.GrantTypesSupported);
    public IEnumerable<string>? ScopesSupported => TryGetStringArray(UdapConstants.Discovery.ScopesSupported);
    public IEnumerable<string>? TokenEndpointAuthMethodsSupported => TryGetStringArray(UdapConstants.Discovery.TokenEndpointAuthMethodsSupported);
    public IEnumerable<string>? TokenEndpointAuthSigningAlgValuesSupported => TryGetStringArray(UdapConstants.Discovery.TokenEndpointAuthSigningAlgValuesSupported);
    public IEnumerable<string>? RegistrationEndpointJwtSigningAlgValuesSupported => TryGetStringArray(UdapConstants.Discovery.RegistrationEndpointJwtSigningAlgValuesSupported);

    public string? JwksUri => TryGetString(UdapConstants.Discovery.JwksUri);
    public string? AuthorizeEndpoint => TryGetString(UdapConstants.Discovery.AuthorizationEndpoint);

    /// <summary>
    /// The FHIR Authorization Server's token endpoint URL
    /// </summary>
    public string? TokenEndpoint => TryGetString(UdapConstants.Discovery.TokenEndpoint);
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

                if (uri == null)
                {
                    return $"{element.Name} endpoint is missing a value";
                }

                if (!isValidUri)
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