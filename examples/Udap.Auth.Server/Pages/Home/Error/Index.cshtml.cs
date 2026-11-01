#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Pages;

namespace Udap.Auth.Server.Pages.Home.Error;

/// <summary>IdentityServer's error page (Duende's default error URL). Details only in Development.</summary>
[AllowAnonymous]
[SecurityHeaders]
public class Index : PageModel
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IWebHostEnvironment _environment;

    public Index(IIdentityServerInteractionService interaction, IWebHostEnvironment environment)
    {
        _interaction = interaction;
        _environment = environment;
    }

    public ErrorMessage? Error { get; private set; }

    public bool ShowDetails => _environment.IsDevelopment();

    public async Task OnGet(string? errorId)
    {
        Error = await _interaction.GetErrorContextAsync(errorId, HttpContext.RequestAborted);
    }

    /// <summary>A plain-language reading of the OAuth error code: what happened and what to do.</summary>
    public (string Title, string Advice) Explain() => Error?.Error switch
    {
        null => ("Sign-in didn't work", "This error has expired or the link is incomplete. Go back to the app and start sign-in again."),
        "access_denied" => ("You chose not to continue", "Nothing was shared. Go back to the app to start again."),
        "unauthorized_client" or "invalid_client" => ("This app isn't set up to sign in here",
            "Its registration with SecuredControls Auth is missing or doesn't allow this kind of sign-in. The app's developer needs to fix it."),
        "invalid_request" => ("The app sent a sign-in request this server can't use",
            "Go back to the app and try again. If it keeps happening, the app's developer needs to check the request."),
        "invalid_scope" => ("The app asked for something this server doesn't offer",
            "The app's developer needs to check which scopes it requests."),
        "login_required" or "consent_required" or "interaction_required" => ("You need to sign in first",
            "Go back to the app and start sign-in again."),
        _ => ("Sign-in didn't work", "Go back to the app and try again. If it keeps happening, contact the app's developer with the request ID below.")
    };
}
