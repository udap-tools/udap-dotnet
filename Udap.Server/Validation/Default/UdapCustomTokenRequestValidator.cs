#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using System.Text.Json;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Configuration;
using Udap.Server.Storage;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Validation.Default;

/// <summary>
/// Custom token request validator that enforces UDAP authorization extension
/// requirements (e.g., hl7-b2b, hl7-b2b-user) for UDAP clients.
/// Profile-specific extensions (e.g., tefca-ias) are supported via
/// <see cref="IAuthorizationExtensionDeserializer"/> registrations.
/// Runs after client authentication succeeds, returning <c>invalid_grant</c>
/// with a descriptive error when required extensions are missing or invalid.
/// </summary>
public class UdapCustomTokenRequestValidator : ICustomTokenRequestValidator
{
    private readonly IUdapAuthorizationExtensionValidator _extensionValidator;
    private readonly IEnumerable<IAuthorizationExtensionDeserializer> _customDeserializers;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ServerSettings _serverSettings;
    private readonly IUdapClientRegistrationStore _store;
    private readonly ILogger<UdapCustomTokenRequestValidator> _logger;

    public UdapCustomTokenRequestValidator(
        IUdapAuthorizationExtensionValidator extensionValidator,
        IEnumerable<IAuthorizationExtensionDeserializer> customDeserializers,
        IHttpContextAccessor httpContextAccessor,
        ServerSettings serverSettings,
        IUdapClientRegistrationStore store,
        ILogger<UdapCustomTokenRequestValidator> logger)
    {
        _extensionValidator = extensionValidator;
        _customDeserializers = customDeserializers;
        _httpContextAccessor = httpContextAccessor;
        _serverSettings = serverSettings;
        _store = store;
        _logger = logger;
    }

    public async Task ValidateAsync(CustomTokenRequestValidationContext context, CancellationToken ct)
    {
        var request = context.Result?.ValidatedRequest;

        if (request == null || !IsUdapClient(request))
        {
            return;
        }

        await AddCommunityClaimAsync(request);

        var clientAssertion = request.Secret?.Credential as string;
        if (clientAssertion == null)
        {
            return;
        }

        var tokenHandler = new JsonWebTokenHandler();
        JsonWebToken jwtToken;

        try
        {
            jwtToken = tokenHandler.ReadJsonWebToken(clientAssertion);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read client assertion JWT for extension validation");
            return;
        }

        Dictionary<string, object>? extensions = null;

        if (jwtToken.TryGetPayloadValue<JsonElement>(UdapConstants.JwtClaimTypes.Extensions, out var extensionsElement)
            && extensionsElement.ValueKind == JsonValueKind.Object)
        {
            extensions = PayloadSerializer.Deserialize(extensionsElement, _customDeserializers);
        }

        var communityId = request.Client.ClientSecrets
            .FirstOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
            ?.Value;

        var sanUri = request.Client.ClientSecrets
            .FirstOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
            ?.Value;

        var extensionContext = new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwtToken,
            ClientId = request.ClientId ?? string.Empty,
            Extensions = extensions,
            CommunityId = communityId,
            GrantType = request.GrantType,
            SanUri = sanUri
        };

        var result = await _extensionValidator.ValidateAsync(extensionContext);

        if (!result.IsValid)
        {
            _logger.LogError(
                "Authorization extension validation failed for client_id {ClientId}: {Error}",
                request.ClientId, result.ErrorDescription);

            if (result.ErrorExtensions != null && _httpContextAccessor.HttpContext != null)
            {
                _httpContextAccessor.HttpContext.Items[UdapServerConstants.HttpContextItems.UdapErrorExtensions] =
                    result.ErrorExtensions;
            }

            context.Result = new TokenRequestValidationResult(
                request,
                result.Error ?? "invalid_grant",
                result.ErrorDescription);
        }
    }

    /// <summary>
    /// When <see cref="ServerSettings.IncludeCommunityClaim"/> is enabled, adds a
    /// <c>udap_community</c> claim to the access token. The value is resolved from the
    /// client's stored community id so a later community rename is reflected automatically.
    /// </summary>
    private async Task AddCommunityClaimAsync(ValidatedTokenRequest request)
    {
        if (!_serverSettings.IncludeCommunityClaim)
        {
            return;
        }

        var communityId = request.Client.ClientSecrets
            .FirstOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
            ?.Value;

        if (string.IsNullOrEmpty(communityId))
        {
            return;
        }

        var communityName = await _store.GetCommunityName(communityId);

        if (string.IsNullOrEmpty(communityName))
        {
            return;
        }

        // Emit the claim without the default "client_" prefix so it appears as "udap_community".
        // UDAP-registered clients carry no other client claims, so clearing the per-request
        // prefix is safe and does not persist. AlwaysSendClientClaims is required so the claim
        // is emitted on the authorization_code flow too (Duende only sends client claims on the
        // client_credentials flow by default).
        request.Client.ClientClaimsPrefix = string.Empty;
        request.Client.AlwaysSendClientClaims = true;
        request.ClientClaims.Add(new Claim(UdapConstants.JwtClaimTypes.UdapCommunity, communityName));
    }

    private static bool IsUdapClient(ValidatedTokenRequest request)
    {
        return request.Client.ClientSecrets
            .Any(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME);
    }
}
