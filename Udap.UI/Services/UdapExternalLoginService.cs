#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Duende.IdentityModel;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Udap.Client;
using Udap.Server.Security.Authentication.TieredOAuth;
using Udap.UI.Pages;

namespace Udap.UI.Services;

public interface IUdapExternalLoginService
{
    /// <summary>
    /// Builds the challenge properties for a UDAP Tiered OAuth login: resolves the upstream IdP from the
    /// <c>idp</c> parameter on the authorize request and discovers its endpoints.
    /// </summary>
    /// <param name="callbackPath">The local path the upstream IdP returns to, e.g. <c>/udaptieredlogin/callback</c>.</param>
    Task<AuthenticationProperties> BuildTieredChallengeAsync(string scheme, string? returnUrl, string callbackPath);

    /// <summary>
    /// Builds the challenge properties for a plain external (OIDC) login.
    /// Throws when <paramref name="returnUrl"/> is neither local nor a valid authorize request.
    /// </summary>
    AuthenticationProperties BuildExternalChallenge(string scheme, string? returnUrl, string callbackUrl);

    /// <summary>
    /// Completes an external or Tiered OAuth login: reads the temporary external cookie, finds or provisions
    /// the local user, issues the local authentication cookie and returns where to send the browser.
    /// </summary>
    Task<UdapInteractionResult> ProcessCallbackAsync(HttpContext httpContext);
}

public class UdapExternalLoginService : IUdapExternalLoginService
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly IUdapUserStore _users;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<UdapExternalLoginService> _logger;

    public UdapExternalLoginService(
        IIdentityServerInteractionService interaction,
        IEventService events,
        IUdapUserStore users,
        IServiceProvider serviceProvider,
        ILogger<UdapExternalLoginService> logger)
    {
        _interaction = interaction;
        _events = events;
        _users = users;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public Task<AuthenticationProperties> BuildTieredChallengeAsync(string scheme, string? returnUrl, string callbackPath)
    {
        // IUdapClient is registered by AddTieredOAuth; resolve it lazily so hosts without Tiered OAuth
        // can still use the rest of this service.
        var udapClient = _serviceProvider.GetService(typeof(IUdapClient)) as IUdapClient
                         ?? throw new InvalidOperationException("IUdapClient is not registered. Call AddTieredOAuth(...) to enable UDAP Tiered OAuth.");

        return TieredOAuthHelpers.BuildDynamicTieredOAuthOptions(
            _interaction,
            udapClient,
            scheme,
            callbackPath,
            string.IsNullOrEmpty(returnUrl) ? "~/" : returnUrl);
    }

    public AuthenticationProperties BuildExternalChallenge(string scheme, string? returnUrl, string callbackUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

        // validate returnUrl - either it is a valid OIDC URL or back to a local page
        if (!UdapReturnUrl.IsLocalUrl(returnUrl) && !_interaction.IsValidReturnUrl(returnUrl))
        {
            // user might have clicked on a malicious link - should be logged
            throw new Exception("invalid return URL");
        }

        // start challenge and roundtrip the return URL and scheme
        return new AuthenticationProperties
        {
            RedirectUri = callbackUrl,
            Items =
            {
                { "returnUrl", returnUrl },
                { "scheme", scheme },
            }
        };
    }

    public async Task<UdapInteractionResult> ProcessCallbackAsync(HttpContext httpContext)
    {
        // read external identity from the temporary cookie
        var result = await httpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (result?.Succeeded != true || result.Principal == null)
        {
            throw new Exception("External authentication error");
        }

        var externalUser = result.Principal;

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            var externalClaims = externalUser.Claims.Select(c => $"{c.Type}: {c.Value}");
            _logger.LogDebug("External claims: {@claims}", externalClaims);
        }

        // the unique id of the external user (issued by the provider) is most commonly
        // the sub claim or the NameIdentifier; other providers may use another claim type
        var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                          externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                          throw new Exception("Unknown userid");

        var provider = result.Properties!.Items["scheme"]!;
        var providerUserId = userIdClaim.Value;

        var user = await _users.FindByExternalProviderAsync(provider, providerUserId, httpContext.RequestAborted);
        if (user == null)
        {
            // this is where a custom registration workflow could start; by default the user is
            // auto-provisioned. Remove the user id claim so it is not stored as an extra claim.
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);
            user = await _users.AutoProvisionAsync(provider, providerUserId, claims, httpContext.RequestAborted);
        }

        // collect protocol data needed later (e.g. for sign-out) into the local auth cookie
        var additionalLocalClaims = new List<Claim>();
        var localSignInProps = new AuthenticationProperties();
        CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);

        var identityServerUser = new IdentityServerUser(user.SubjectId)
        {
            DisplayName = user.Username,
            IdentityProvider = provider,
            AdditionalClaims = additionalLocalClaims
        };

        await httpContext.SignInAsync(identityServerUser, localSignInProps);

        // delete temporary cookie used during external authentication
        await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

        // check if external login is in the context of an OIDC request
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl, httpContext.RequestAborted);
        await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.SubjectId, user.Username, true, context?.Client.ClientId), httpContext.RequestAborted);

        if (context != null && context.IsNativeClient())
        {
            return UdapInteractionResult.NativeClientRedirect(returnUrl);
        }

        return UdapInteractionResult.Redirect(returnUrl);
    }

    // if the external login is OIDC-based, there are certain things we need to preserve to make logout work
    // this will be different for WS-Fed, SAML2p or other protocols
    private static void CaptureExternalLoginContext(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
    {
        // if the external system sent a session id claim, copy it over so we can use it for single sign-out
        var sid = externalResult.Principal!.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
        if (sid != null)
        {
            localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
        }

        // if the external provider issued an id_token, we'll keep it for signout
        var idToken = externalResult.Properties!.GetTokenValue("id_token");
        if (idToken != null)
        {
            localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
        }
    }
}
