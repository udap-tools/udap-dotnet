using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Services;

namespace Udap.UI.Pages.ExternalLogin;

[AllowAnonymous]
[SecurityHeaders]
public class Callback : PageModel
{
    private readonly IServiceProvider _services;

    public Callback(IServiceProvider services)
    {
        // the callback logic lives in IUdapExternalLoginService; plug in your own identity store by registering an IUdapUserStore
        _services = services;
    }

    public async Task<IActionResult> OnGet()
    {
        var result = await _services.GetUdapExternalLoginService().ProcessCallbackAsync(HttpContext);
        return this.ToActionResult(result);
    }
}
