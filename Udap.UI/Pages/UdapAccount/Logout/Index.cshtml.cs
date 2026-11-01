using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Services;

namespace Udap.UI.Pages.UdapAccount.Logout;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly IServiceProvider _services;

    [BindProperty] 
    public string LogoutId { get; set; }

    public Index(IServiceProvider services)
    {
        _services = services;
    }

    private IUdapLogoutService LogoutService => _services.GetUdapLogoutService();

    public async Task<IActionResult> OnGet(string logoutId)
    {
        LogoutId = logoutId;

        if (!await LogoutService.ShouldShowLogoutPromptAsync(HttpContext, LogoutId))
        {
            // if the request for logout was properly authenticated from IdentityServer, then
            // we don't need to show the prompt and can just log the user out directly.
            return await OnPost();
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        var result = await LogoutService.SignOutAsync(HttpContext, LogoutId);
        LogoutId = result.LogoutId;

        if (result.ExternalSignOutScheme != null)
        {
            // build a return URL so the upstream provider will redirect back
            // to us after the user has logged out. this allows us to then
            // complete our single sign-out processing.
            string url = Url.Page("/Account/Logout/Loggedout", new { logoutId = LogoutId });

            // this triggers a redirect to the external provider for sign-out
            return SignOut(new AuthenticationProperties { RedirectUri = url }, result.ExternalSignOutScheme);
        }

        return RedirectToPage("/Account/Logout/LoggedOut", new { logoutId = LogoutId });
    }
}
