#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Pages;
using Udap.UI.Services;

namespace Udap.Auth.Server.Pages.UdapAccount.Logout;

/// <summary>Sign-out prompt (Duende LogoutUrl /udapaccount/logout). Logic: Udap.UI's <see cref="IUdapLogoutService"/>.</summary>
[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly IUdapLogoutService _logout;

    public Index(IUdapLogoutService logout)
    {
        _logout = logout;
    }

    [BindProperty]
    public string? LogoutId { get; set; }

    public async Task<IActionResult> OnGet(string? logoutId)
    {
        LogoutId = logoutId;

        if (!await _logout.ShouldShowLogoutPromptAsync(HttpContext, LogoutId))
        {
            // a logout request IdentityServer authenticated, or nobody is signed in: no need to ask
            return await OnPost();
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        var result = await _logout.SignOutAsync(HttpContext, LogoutId);

        if (result.ExternalSignOutScheme != null)
        {
            // sign out of the upstream provider too; it returns to the logged-out page
            var url = Url.Page("/UdapAccount/Logout/LoggedOut", new { logoutId = result.LogoutId });
            return SignOut(new AuthenticationProperties { RedirectUri = url }, result.ExternalSignOutScheme);
        }

        return RedirectToPage("/UdapAccount/Logout/LoggedOut", new { logoutId = result.LogoutId });
    }
}
