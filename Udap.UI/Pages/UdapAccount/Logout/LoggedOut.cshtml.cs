using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Services;

namespace Udap.UI.Pages.UdapAccount.Logout;

[SecurityHeaders]
[AllowAnonymous]
public class LoggedOut : PageModel
{
    private readonly IServiceProvider _services;
        
    public LoggedOutViewModel View { get; set; }

    public LoggedOut(IServiceProvider services)
    {
        _services = services;
    }

    public async Task OnGet(string logoutId)
    {
        // get context information (client name, post logout redirect URI and iframe for federated signout)
        var logout = await _services.GetUdapLogoutService().GetLoggedOutContextAsync(HttpContext, logoutId);

        View = new LoggedOutViewModel
        {
            AutomaticRedirectAfterSignOut = logout.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout.PostLogoutRedirectUri,
            ClientName = logout.ClientName,
            SignOutIframeUrl = logout.SignOutIframeUrl
        };
    }
}
