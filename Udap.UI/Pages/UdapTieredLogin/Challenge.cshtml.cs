#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Udap.Client.Client;
using Udap.Server.Security.Authentication.TieredOAuth;

namespace Udap.UI.Pages.UdapTieredLogin;

[AllowAnonymous]
[SecurityHeaders]
public class Challenge : PageModel
{
    private readonly IIdentityServerInteractionService _interactionService;
    private readonly IUdapClient _udapClient;
    private readonly ILogger<Challenge> _logger;

    public Challenge(IIdentityServerInteractionService interactionService, IUdapClient udapClient, ILogger<Challenge> logger)
    {
        _interactionService = interactionService;
        _udapClient = udapClient;
        _logger = logger;
    }
        
    public async Task<IActionResult> OnGetAsync(string scheme, string returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

        try
        {
            var props = await TieredOAuthHelpers.BuildDynamicTieredOAuthOptions(
                _interactionService,
                _udapClient,
                scheme,
                "/udaptieredlogin/callback",
                returnUrl);

            // start challenge and roundtrip the return URL and scheme 
            return Challenge(props, scheme);
        }
        catch (Exception ex)
        {
            _logger.LogWarning($"Failed Tiered Oauth for returnUrl: {returnUrl}");
        }

        return Page();
    }
}