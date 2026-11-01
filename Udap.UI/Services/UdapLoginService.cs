#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Web;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Udap.Server.Security.Authentication.TieredOAuth;
using Udap.UI.Options;
using Udap.UI.Pages;

namespace Udap.UI.Services;

/// <summary>
/// An external (or UDAP Tiered OAuth) login option offered on the login page.
/// </summary>
public class UdapExternalProvider
{
    public string? DisplayName { get; set; }
    public string? AuthenticationScheme { get; set; }
    public string? ReturnUrl { get; set; }

    /// <summary>The UDAP <c>idp</c> hint carried on the authorize request, if any.</summary>
    public string? TieredOAuthIdp { get; set; }

    public bool IsTieredOAuth => AuthenticationScheme == TieredOAuthAuthenticationDefaults.AuthenticationScheme;
}

/// <summary>
/// Everything a login page needs to render, without any markup decisions.
/// </summary>
public class UdapLoginContext
{
    public string? ReturnUrl { get; set; }
    public string? LoginHint { get; set; }
    public bool EnableLocalLogin { get; set; } = true;
    public bool AllowRememberLogin { get; set; } = true;

    /// <summary>The client application the user is signing in to, when in an authorize request.</summary>
    public Duende.IdentityServer.Models.Client? Client { get; set; }

    public IReadOnlyList<UdapExternalProvider> ExternalProviders { get; set; } = Array.Empty<UdapExternalProvider>();

    public bool IsExternalLoginOnly => !EnableLocalLogin && ExternalProviders.Count == 1;
    public string? ExternalLoginScheme => ExternalProviders.Count == 1 ? ExternalProviders[0].AuthenticationScheme : null;
}

public interface IUdapLoginService
{
    /// <summary>Builds the login page context for <paramref name="returnUrl"/>.</summary>
    Task<UdapLoginContext> BuildLoginContextAsync(HttpContext httpContext, string? returnUrl);

    /// <summary>
    /// The user cancelled. Denies the authorize request (an <c>access_denied</c> response to the client)
    /// or sends the user home when there is no request.
    /// </summary>
    Task<UdapInteractionResult> CancelAsync(HttpContext httpContext, string? returnUrl);

    /// <summary>
    /// Validates local credentials and issues the authentication cookie.
    /// Returns <see cref="UdapInteractionResultKind.ShowPage"/> with an error message when the credentials are invalid.
    /// Throws when the return URL is neither an authorize request nor a local URL.
    /// </summary>
    Task<UdapInteractionResult> SignInLocalAsync(HttpContext httpContext, string username, string password, bool rememberLogin, string? returnUrl);

    /// <summary>
    /// Issues the authentication cookie for an already verified user (for example after a passkey ceremony
    /// or account registration) and returns where to send the browser.
    /// </summary>
    Task<UdapInteractionResult> SignInUserAsync(HttpContext httpContext, UdapUser user, bool rememberLogin, string? returnUrl, string? authenticationMethod = null);
}

public class UdapLoginService : IUdapLoginService
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore;
    private readonly IEventService _events;
    private readonly IUdapUserStore _users;
    private readonly UdapUILoginOptions _options;

    public UdapLoginService(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IIdentityProviderStore identityProviderStore,
        IEventService events,
        IUdapUserStore users,
        IOptions<UdapUIOptions> options)
    {
        _interaction = interaction;
        _schemeProvider = schemeProvider;
        _identityProviderStore = identityProviderStore;
        _events = events;
        _users = users;
        _options = options.Value.Login;
    }

    public async Task<UdapLoginContext> BuildLoginContextAsync(HttpContext httpContext, string? returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl, httpContext.RequestAborted);

        // The authorize request named a specific scheme (acr_values idp:...): short circuit the UI to that one.
        // This is Duende's IdP hint, not the UDAP Tiered OAuth "idp" parameter.
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

            return new UdapLoginContext
            {
                ReturnUrl = returnUrl,
                LoginHint = context.LoginHint,
                EnableLocalLogin = local,
                AllowRememberLogin = _options.AllowRememberLogin,
                Client = context.Client,
                ExternalProviders = local
                    ? Array.Empty<UdapExternalProvider>()
                    : new[] { new UdapExternalProvider { AuthenticationScheme = context.IdP, ReturnUrl = returnUrl } }
            };
        }

        string? tieredOAuthIdp = null;
        if (!string.IsNullOrEmpty(returnUrl) &&
            QueryHelpers.ParseQuery(HttpUtility.UrlDecode(returnUrl)).TryGetValue("idp", out var udapIdp))
        {
            tieredOAuthIdp = udapIdp.FirstOrDefault();
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new UdapExternalProvider
            {
                DisplayName = x.DisplayName ?? x.Name,
                AuthenticationScheme = x.Name,
                ReturnUrl = returnUrl,
                TieredOAuthIdp = tieredOAuthIdp
            })
            .ToList();

        var dynamicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync(httpContext.RequestAborted))
            .Where(x => x.Enabled)
            .Select(x => new UdapExternalProvider
            {
                AuthenticationScheme = x.Scheme,
                DisplayName = x.DisplayName,
                ReturnUrl = returnUrl
            });

        providers.AddRange(dynamicSchemes);

        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
            {
                providers = providers
                    .Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme!))
                    .ToList();
            }
        }

        return new UdapLoginContext
        {
            ReturnUrl = returnUrl,
            LoginHint = context?.LoginHint,
            AllowRememberLogin = _options.AllowRememberLogin,
            EnableLocalLogin = allowLocal && _options.AllowLocalLogin,
            Client = client,
            ExternalProviders = providers
        };
    }

    public async Task<UdapInteractionResult> CancelAsync(HttpContext httpContext, string? returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl, httpContext.RequestAborted);

        if (context == null)
        {
            // since we don't have a valid context, then we just go back to the home page
            return UdapInteractionResult.Redirect("~/");
        }

        // if the user cancels, send a result back into IdentityServer as if they
        // denied the consent (even if this client does not require consent).
        // this will send back an access denied OIDC error response to the client.
        await _interaction.DenyAuthorizationAsync(context, InteractionError.AccessDenied, httpContext.RequestAborted);

        // we can trust returnUrl since GetAuthorizationContextAsync returned non-null
        return context.IsNativeClient()
            ? UdapInteractionResult.NativeClientRedirect(returnUrl!)
            : UdapInteractionResult.Redirect(returnUrl!);
    }

    public async Task<UdapInteractionResult> SignInLocalAsync(HttpContext httpContext, string username, string password, bool rememberLogin, string? returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl, httpContext.RequestAborted);

        var user = await _users.ValidateCredentialsAsync(username, password, httpContext.RequestAborted);
        if (user == null)
        {
            await _events.RaiseAsync(new UserLoginFailureEvent(username, "invalid credentials", clientId: context?.Client.ClientId), httpContext.RequestAborted);
            return UdapInteractionResult.ShowPage(_options.InvalidCredentialsErrorMessage);
        }

        return await SignInUserAsync(httpContext, user, rememberLogin, returnUrl);
    }

    public async Task<UdapInteractionResult> SignInUserAsync(HttpContext httpContext, UdapUser user, bool rememberLogin, string? returnUrl, string? authenticationMethod = null)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl, httpContext.RequestAborted);

        // Validate the return URL before issuing the cookie, so a malicious link never ends in a signed-in redirect.
        var destination = ResolveReturnUrl(context, returnUrl);

        await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.Client.ClientId), httpContext.RequestAborted);

        // only set explicit expiration here if user chooses "remember me".
        // otherwise we rely upon expiration configured in cookie middleware.
        AuthenticationProperties? props = null;
        if (_options.AllowRememberLogin && rememberLogin)
        {
            props = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.Add(_options.RememberMeLoginDuration)
            };
        }

        var identityServerUser = new IdentityServerUser(user.SubjectId)
        {
            DisplayName = user.Username
        };

        if (!string.IsNullOrEmpty(authenticationMethod))
        {
            identityServerUser.AuthenticationMethods = new List<string> { authenticationMethod };
        }

        await httpContext.SignInAsync(identityServerUser, props);

        return destination;
    }

    private static UdapInteractionResult ResolveReturnUrl(AuthorizationRequest? context, string? returnUrl)
    {
        if (context != null)
        {
            // we can trust returnUrl since GetAuthorizationContextAsync returned non-null
            return context.IsNativeClient()
                ? UdapInteractionResult.NativeClientRedirect(returnUrl!)
                : UdapInteractionResult.Redirect(returnUrl!);
        }

        if (UdapReturnUrl.IsLocalUrl(returnUrl))
        {
            return UdapInteractionResult.Redirect(returnUrl!);
        }

        if (string.IsNullOrEmpty(returnUrl))
        {
            return UdapInteractionResult.Redirect("~/");
        }

        // user might have clicked on a malicious link - should be logged
        throw new Exception("invalid return URL");
    }
}
