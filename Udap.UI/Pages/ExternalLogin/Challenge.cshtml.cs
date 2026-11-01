using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Services;

namespace Udap.UI.Pages.ExternalLogin;

[AllowAnonymous]
[SecurityHeaders]
public class Challenge : PageModel
{
    private readonly IServiceProvider _services;

    public Challenge(IServiceProvider services)
    {
        _services = services;
    }
        
    public IActionResult OnGet(string scheme, string returnUrl)
    {
        // start challenge and roundtrip the return URL and scheme 
        var props = _services.GetUdapExternalLoginService()
            .BuildExternalChallenge(scheme, returnUrl, Url.Page("/externallogin/callback")!);

        return Challenge(props, scheme);
    }
}
