#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Pages;

namespace Udap.UI.Services;

public enum UdapInteractionResultKind
{
    /// <summary>Redirect the browser to <see cref="UdapInteractionResult.Url"/>.</summary>
    Redirect,

    /// <summary>
    /// The client is native; render the loading page that redirects to <see cref="UdapInteractionResult.Url"/>
    /// for a better end-user experience.
    /// </summary>
    NativeClientRedirect,

    /// <summary>Re-display the current page, showing <see cref="UdapInteractionResult.Error"/> when set.</summary>
    ShowPage
}

/// <summary>
/// The outcome of an interaction service call, independent of any page or markup.
/// Host pages translate it into an <see cref="IActionResult"/>, usually with
/// <see cref="UdapInteractionResultExtensions.ToActionResult"/>.
/// </summary>
public sealed record UdapInteractionResult(UdapInteractionResultKind Kind, string? Url = null, string? Error = null)
{
    public static UdapInteractionResult Redirect(string url) => new(UdapInteractionResultKind.Redirect, url);

    public static UdapInteractionResult NativeClientRedirect(string url) => new(UdapInteractionResultKind.NativeClientRedirect, url);

    public static UdapInteractionResult ShowPage(string? error = null) => new(UdapInteractionResultKind.ShowPage, Error: error);

    public bool IsShowPage => Kind == UdapInteractionResultKind.ShowPage;
}

public static class UdapInteractionResultExtensions
{
    /// <summary>
    /// Converts a redirecting <see cref="UdapInteractionResult"/> into the page's action result.
    /// Callers handle <see cref="UdapInteractionResultKind.ShowPage"/> themselves, because only the
    /// page knows how to rebuild its view model.
    /// </summary>
    public static IActionResult ToActionResult(this PageModel page, UdapInteractionResult result)
    {
        return result.Kind switch
        {
            UdapInteractionResultKind.Redirect => new RedirectResult(result.Url!),
            UdapInteractionResultKind.NativeClientRedirect => page.LoadingPage(result.Url!),
            _ => throw new InvalidOperationException("A ShowPage result must be rendered by the page.")
        };
    }
}
