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
using Microsoft.Extensions.Logging;
using Udap.UI.Services;

namespace Udap.UI.Pages.UdapTieredLogin;

[AllowAnonymous]
[SecurityHeaders]
public class Challenge : PageModel
{
    private readonly IServiceProvider _services;
    private readonly ILogger<Challenge> _logger;

    public Challenge(IServiceProvider services, ILogger<Challenge> logger)
    {
        _services = services;
        _logger = logger;
    }
        
    public async Task<IActionResult> OnGetAsync(string scheme, string returnUrl)
    {
        try
        {
            var props = await _services.GetUdapExternalLoginService()
                .BuildTieredChallengeAsync(scheme, returnUrl, "/udaptieredlogin/callback");

            // start challenge and roundtrip the return URL and scheme 
            return Challenge(props, scheme);
        }
        catch (Exception ex)
        {
            // returnUrl comes from the query string: strip line breaks so it cannot forge log lines.
            _logger.LogWarning(ex, "Failed Tiered OAuth for returnUrl: {ReturnUrl}",
                returnUrl?.Replace("\r", "").Replace("\n", ""));
        }

        return Page();
    }
}
