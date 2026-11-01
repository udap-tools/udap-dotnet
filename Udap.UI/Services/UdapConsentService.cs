#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityModel;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.UI.Options;
using Udap.UI.Pages;

namespace Udap.UI.Services;

public class UdapScopeResource
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
}

/// <summary>
/// One permission shown to the user on a consent screen.
/// </summary>
public class UdapScope
{
    /// <summary>Parsed scope name (no parameter); empty for offline_access.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Raw scope value posted back when consented.</summary>
    public string Value { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Emphasize { get; set; }
    public bool Required { get; set; }
    public bool Checked { get; set; }
    public IReadOnlyList<UdapScopeResource> Resources { get; set; } = Array.Empty<UdapScopeResource>();
}

public class UdapScopeList
{
    public IReadOnlyList<UdapScope> IdentityScopes { get; set; } = Array.Empty<UdapScope>();
    public IReadOnlyList<UdapScope> ApiScopes { get; set; } = Array.Empty<UdapScope>();
}

/// <summary>
/// Builds the consent permission list for the authorize, device and CIBA consent screens.
/// </summary>
public static class UdapScopeListBuilder
{
    /// <param name="resources">The validated resources of the request.</param>
    /// <param name="resourceIndicators">Requested resource indicators, used to show which API each scope reaches.</param>
    /// <param name="scopesConsented">The scopes the user previously ticked, or null on first display (everything checked).</param>
    public static UdapScopeList Build(
        ResourceValidationResult resources,
        IEnumerable<string>? resourceIndicators,
        IEnumerable<string>? scopesConsented,
        UdapUIConsentOptions options)
    {
        var consented = scopesConsented?.ToHashSet();
        bool IsChecked(string value) => consented == null || consented.Contains(value);

        var identityScopes = resources.Resources.IdentityResources
            .Select(x => new UdapScope
            {
                Name = x.Name,
                Value = x.Name,
                DisplayName = x.DisplayName ?? x.Name,
                Description = x.Description,
                Emphasize = x.Emphasize,
                Required = x.Required,
                Checked = IsChecked(x.Name) || x.Required
            })
            .ToList();

        var indicators = resourceIndicators?.ToHashSet() ?? new HashSet<string>();
        var apiResources = resources.Resources.ApiResources.Where(x => indicators.Contains(x.Name)).ToList();

        var apiScopes = new List<UdapScope>();
        foreach (var parsedScope in resources.ParsedScopes)
        {
            var apiScope = resources.Resources.FindApiScope(parsedScope.ParsedName);
            if (apiScope == null)
            {
                continue;
            }

            var displayName = apiScope.DisplayName ?? apiScope.Name;
            if (!string.IsNullOrWhiteSpace(parsedScope.ParsedParameter))
            {
                displayName += ":" + parsedScope.ParsedParameter;
            }

            apiScopes.Add(new UdapScope
            {
                Name = parsedScope.ParsedName,
                Value = parsedScope.RawValue,
                DisplayName = displayName,
                Description = apiScope.Description,
                Emphasize = apiScope.Emphasize,
                Required = apiScope.Required,
                Checked = IsChecked(parsedScope.RawValue) || apiScope.Required,
                Resources = apiResources
                    .Where(x => x.Scopes.Contains(parsedScope.ParsedName))
                    .Select(x => new UdapScopeResource { Name = x.Name, DisplayName = x.DisplayName ?? x.Name })
                    .ToList()
            });
        }

        if (options.EnableOfflineAccess && resources.Resources.OfflineAccess)
        {
            apiScopes.Add(new UdapScope
            {
                Value = IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = options.OfflineAccessDisplayName,
                Description = options.OfflineAccessDescription,
                Emphasize = true,
                Checked = IsChecked(IdentityServerConstants.StandardScopes.OfflineAccess)
            });
        }

        return new UdapScopeList { IdentityScopes = identityScopes, ApiScopes = apiScopes };
    }

    /// <summary>
    /// Turns the user's consent form submission into a <see cref="ConsentResponse"/>.
    /// Returns a null response with an error message when the selection is not valid.
    /// </summary>
    /// <param name="button">"yes" to grant, "no" to deny.</param>
    public static (ConsentResponse? Response, string? Error) Decide(
        string? button,
        IEnumerable<string>? scopesConsented,
        bool rememberConsent,
        string? description,
        UdapUIConsentOptions options)
    {
        if (button == "no")
        {
            return (new ConsentResponse { Error = InteractionError.AccessDenied }, null);
        }

        if (button != "yes")
        {
            return (null, options.InvalidSelectionErrorMessage);
        }

        var scopes = scopesConsented?.ToList() ?? new List<string>();
        if (!scopes.Any())
        {
            return (null, options.MustChooseOneErrorMessage);
        }

        if (!options.EnableOfflineAccess)
        {
            scopes = scopes.Where(x => x != IdentityServerConstants.StandardScopes.OfflineAccess).ToList();
        }

        return (new ConsentResponse
        {
            RememberConsent = rememberConsent,
            ScopesValuesConsented = scopes.ToArray(),
            Description = description
        }, null);
    }
}

/// <summary>
/// Everything an authorize-request consent page needs to render.
/// </summary>
public class UdapConsentContext
{
    public required Duende.IdentityServer.Models.Client Client { get; init; }
    public string ClientName => Client.ClientName ?? Client.ClientId;
    public string? ClientUrl => Client.ClientUri;
    public string? ClientLogoUrl => Client.LogoUri;
    public bool AllowRememberConsent => Client.AllowRememberConsent;
    public required UdapScopeList Scopes { get; init; }
}

public interface IUdapConsentService
{
    /// <summary>Returns null when <paramref name="returnUrl"/> is no longer a valid authorize request.</summary>
    Task<UdapConsentContext?> BuildConsentContextAsync(HttpContext httpContext, string? returnUrl, IEnumerable<string>? scopesConsented = null);

    /// <summary>
    /// Records the user's decision. Returns null when <paramref name="returnUrl"/> is no longer a valid
    /// authorize request, <see cref="UdapInteractionResultKind.ShowPage"/> with an error when the selection is
    /// invalid, otherwise where to send the browser.
    /// </summary>
    Task<UdapInteractionResult?> ProcessConsentAsync(
        HttpContext httpContext,
        string? returnUrl,
        string? button,
        IEnumerable<string>? scopesConsented,
        bool rememberConsent,
        string? description);
}

public class UdapConsentService : IUdapConsentService
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly ILogger<UdapConsentService> _logger;
    private readonly UdapUIConsentOptions _options;

    public UdapConsentService(
        IIdentityServerInteractionService interaction,
        IEventService events,
        IOptions<UdapUIOptions> options,
        ILogger<UdapConsentService> logger)
    {
        _interaction = interaction;
        _events = events;
        _logger = logger;
        _options = options.Value.Consent;
    }

    public async Task<UdapConsentContext?> BuildConsentContextAsync(HttpContext httpContext, string? returnUrl, IEnumerable<string>? scopesConsented = null)
    {
        var request = await _interaction.GetAuthorizationContextAsync(returnUrl, httpContext.RequestAborted);
        if (request == null)
        {
            // returnUrl comes from the request: strip line breaks so it cannot forge log lines.
            _logger.LogError("No consent request matching request: {ReturnUrl}",
                returnUrl?.Replace("\r", "").Replace("\n", ""));
            return null;
        }

        var resourceIndicators = request.Parameters.GetValues(OidcConstants.AuthorizeRequest.Resource);

        return new UdapConsentContext
        {
            Client = request.Client,
            Scopes = UdapScopeListBuilder.Build(request.ValidatedResources, resourceIndicators, scopesConsented, _options)
        };
    }

    public async Task<UdapInteractionResult?> ProcessConsentAsync(
        HttpContext httpContext,
        string? returnUrl,
        string? button,
        IEnumerable<string>? scopesConsented,
        bool rememberConsent,
        string? description)
    {
        var request = await _interaction.GetAuthorizationContextAsync(returnUrl, httpContext.RequestAborted);
        if (request == null)
        {
            return null;
        }

        var (response, error) = UdapScopeListBuilder.Decide(button, scopesConsented, rememberConsent, description, _options);
        if (response == null)
        {
            return UdapInteractionResult.ShowPage(error);
        }

        var subjectId = httpContext.User.GetSubjectId();
        if (response.Error != null)
        {
            await _events.RaiseAsync(new ConsentDeniedEvent(subjectId, request.Client.ClientId, request.ValidatedResources.RawScopeValues), httpContext.RequestAborted);
        }
        else
        {
            await _events.RaiseAsync(new ConsentGrantedEvent(subjectId, request.Client.ClientId, request.ValidatedResources.RawScopeValues, response.ScopesValuesConsented, response.RememberConsent), httpContext.RequestAborted);
        }

        // communicate outcome of consent back to identityserver, then back to the authorization endpoint
        await _interaction.GrantConsentAsync(request, response, httpContext.RequestAborted);

        return request.IsNativeClient()
            ? UdapInteractionResult.NativeClientRedirect(returnUrl!)
            : UdapInteractionResult.Redirect(returnUrl!);
    }
}
