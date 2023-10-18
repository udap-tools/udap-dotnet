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
using Udap.Client.Client;
using Udap.Server.Security.Authentication.TieredOAuth;

namespace Udap.Auth.Server.Pages.UdapTieredLogin;

[AllowAnonymous]
[SecurityHeaders]
public class Challenge : PageModel
{
    private readonly IIdentityServerInteractionService _interactionService;
    private readonly IUdapClient _udapClient;

    public Challenge(IIdentityServerInteractionService interactionService, IUdapClient udapClient)
    {
        _interactionService = interactionService;
        _udapClient = udapClient;
    }
        
    public async Task<IActionResult> OnGetAsync(string scheme, string returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";
        
        var  props = await TieredOAuthHelpers.BuildDynamicTieredOAuthOptions(
            _interactionService, 
            _udapClient,
            scheme,
            "/udaptieredlogin/callback",
            returnUrl);

        // start challenge and roundtrip the return URL and scheme 
        return Challenge(props, scheme);
    }
}