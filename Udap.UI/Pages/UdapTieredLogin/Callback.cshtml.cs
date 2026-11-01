#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Services;

namespace Udap.UI.Pages.UdapTieredLogin;

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
