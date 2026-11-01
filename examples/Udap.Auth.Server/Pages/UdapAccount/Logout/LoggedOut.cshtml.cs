#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Pages;
using Udap.UI.Services;

namespace Udap.Auth.Server.Pages.UdapAccount.Logout;

[SecurityHeaders]
[AllowAnonymous]
public class LoggedOut : PageModel
{
    private readonly IUdapLogoutService _logout;

    public LoggedOut(IUdapLogoutService logout)
    {
        _logout = logout;
    }

    public UdapLoggedOutContext View { get; private set; } = new();

    public async Task OnGet(string? logoutId)
    {
        View = await _logout.GetLoggedOutContextAsync(HttpContext, logoutId);
    }
}
