#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Messages;
using Udap.Common.Extensions;
using Udap.Model;

namespace Udap.Client;

/// <summary>
/// Reads the endpoint claims from a server's signed metadata. Per the UDAP Security IG (Section 2.3),
/// values in <c>signed_metadata</c> take precedence over the plain JSON elements, <c>token_endpoint</c>
/// and <c>registration_endpoint</c> are required claims, and <c>authorization_endpoint</c> is required
/// when the plain JSON includes one.
/// </summary>
internal static class SignedMetadataEndpoints
{
    /// <summary>
    /// Returns the endpoint claims of an already validated signed metadata JWT, checked against the same
    /// discovery policy rules (https, host) the plain JSON endpoints were checked against.
    /// </summary>
    /// <exception cref="SecurityTokenException">A required claim is missing or an endpoint breaks the policy.</exception>
    public static IReadOnlyDictionary<string, string> Resolve(
        string signedMetadata,
        UdapMetadata unsignedMetadata,
        DiscoveryPolicy policy,
        ILogger logger)
    {
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(signedMetadata);
        var endpoints = new Dictionary<string, string>();

        foreach (var name in new[] { UdapConstants.Discovery.TokenEndpoint, UdapConstants.Discovery.RegistrationEndpoint })
        {
            endpoints[name] = Claim(jwt, name)
                ?? throw new SecurityTokenException($"signed_metadata is missing the required {name} claim.");
        }

        var authorization = Claim(jwt, UdapConstants.Discovery.AuthorizationEndpoint);
        if (authorization != null)
        {
            endpoints[UdapConstants.Discovery.AuthorizationEndpoint] = authorization;
        }
        else if (unsignedMetadata.AuthorizationEndpoint.IsPresent())
        {
            throw new SecurityTokenException(
                $"signed_metadata is missing the {UdapConstants.Discovery.AuthorizationEndpoint} claim, which is required when the metadata includes one.");
        }

        using (var document = JsonDocument.Parse(JsonSerializer.Serialize(endpoints)))
        {
            var error = UdapDiscoveryDocumentResponse.ValidateEndpoints(document.RootElement, policy);
            if (error.IsPresent())
            {
                throw new SecurityTokenException($"signed_metadata endpoint rejected: {error}");
            }
        }

        foreach (var (name, signedValue) in endpoints)
        {
            var unsignedValue = Unsigned(unsignedMetadata, name);
            if (unsignedValue.IsPresent() && !string.Equals(unsignedValue, signedValue, StringComparison.Ordinal))
            {
                logger.LogWarning(
                    "UDAP metadata {Endpoint} differs between the plain JSON ({Unsigned}) and signed_metadata ({Signed}); using the signed value",
                    name, unsignedValue, signedValue);
            }
        }

        return endpoints;
    }

    /// <summary>Writes the signed endpoint values over the plain JSON values in <paramref name="metadata"/>.</summary>
    public static void Apply(UdapMetadata metadata, IReadOnlyDictionary<string, string> endpoints)
    {
        metadata.TokenEndpoint = endpoints[UdapConstants.Discovery.TokenEndpoint];
        metadata.RegistrationEndpoint = endpoints[UdapConstants.Discovery.RegistrationEndpoint];
        if (endpoints.TryGetValue(UdapConstants.Discovery.AuthorizationEndpoint, out var authorization))
        {
            metadata.AuthorizationEndpoint = authorization;
        }
    }

    private static string? Claim(JsonWebToken jwt, string name) =>
        jwt.TryGetPayloadValue<string>(name, out var value) && value.IsPresent() ? value : null;

    private static string? Unsigned(UdapMetadata metadata, string name) => name switch
    {
        UdapConstants.Discovery.TokenEndpoint => metadata.TokenEndpoint,
        UdapConstants.Discovery.RegistrationEndpoint => metadata.RegistrationEndpoint,
        UdapConstants.Discovery.AuthorizationEndpoint => metadata.AuthorizationEndpoint,
        _ => null
    };
}
