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
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Udap.UI.Options;
using Udap.UI.Pages;

namespace Udap.UI.Services;

/// <summary>
/// The result of signing the user out locally.
/// </summary>
/// <param name="LogoutId">The logout context id to carry to the logged-out page.</param>
/// <param name="ExternalSignOutScheme">
/// When set, the user signed in through this external scheme and it supports sign-out: the page should
/// return <c>SignOut(new AuthenticationProperties { RedirectUri = loggedOutUrl }, scheme)</c> so the
/// upstream provider signs out too and then redirects back.
/// </param>
public sealed record UdapSignOutResult(string? LogoutId, string? ExternalSignOutScheme);

public class UdapLoggedOutContext
{
    public string? PostLogoutRedirectUri { get; set; }
    public string? ClientName { get; set; }
    public string? SignOutIframeUrl { get; set; }
    public bool AutomaticRedirectAfterSignOut { get; set; }
}

public interface IUdapLogoutService
{
    /// <summary>True when the user should be asked to confirm sign-out.</summary>
    Task<bool> ShouldShowLogoutPromptAsync(HttpContext httpContext, string? logoutId);

    /// <summary>Signs the user out of this server and reports whether an upstream sign-out is needed.</summary>
    Task<UdapSignOutResult> SignOutAsync(HttpContext httpContext, string? logoutId);

    Task<UdapLoggedOutContext> GetLoggedOutContextAsync(HttpContext httpContext, string? logoutId);
}

public class UdapLogoutService : IUdapLogoutService
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly UdapUILogoutOptions _options;

    public UdapLogoutService(IIdentityServerInteractionService interaction, IEventService events, IOptions<UdapUIOptions> options)
    {
        _interaction = interaction;
        _events = events;
        _options = options.Value.Logout;
    }

    public async Task<bool> ShouldShowLogoutPromptAsync(HttpContext httpContext, string? logoutId)
    {
        if (httpContext.User?.Identity?.IsAuthenticated != true)
        {
            // if the user is not authenticated, then just show logged out page
            return false;
        }

        var context = await _interaction.GetLogoutContextAsync(logoutId, httpContext.RequestAborted);
        if (context?.ShowSignoutPrompt == false)
        {
            // the request for logout was properly authenticated from IdentityServer: it's safe to sign out
            return false;
        }

        return _options.ShowLogoutPrompt;
    }

    public async Task<UdapSignOutResult> SignOutAsync(HttpContext httpContext, string? logoutId)
    {
        var user = httpContext.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            return new UdapSignOutResult(logoutId, null);
        }

        // if there's no current logout context, create one; this captures necessary info from the
        // current logged in user. this can still return null if there is no context needed
        logoutId ??= await _interaction.CreateLogoutContextAsync(httpContext.RequestAborted);

        // delete local authentication cookie
        await httpContext.SignOutAsync();

        await _events.RaiseAsync(new UserLogoutSuccessEvent(user.GetSubjectId(), user.GetDisplayName()), httpContext.RequestAborted);

        // see if we need to trigger federated logout; a local login can ignore this workflow
        var idp = user.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
        if (idp != null &&
            idp != IdentityServerConstants.LocalIdentityProvider &&
            await httpContext.GetSchemeSupportsSignOutAsync(idp))
        {
            return new UdapSignOutResult(logoutId, idp);
        }

        return new UdapSignOutResult(logoutId, null);
    }

    public async Task<UdapLoggedOutContext> GetLoggedOutContextAsync(HttpContext httpContext, string? logoutId)
    {
        // client name, post logout redirect URI and iframe for federated signout
        var logout = await _interaction.GetLogoutContextAsync(logoutId, httpContext.RequestAborted);

        return new UdapLoggedOutContext
        {
            AutomaticRedirectAfterSignOut = _options.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
            ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
            SignOutIframeUrl = logout?.SignOutIFrameUrl
        };
    }
}
