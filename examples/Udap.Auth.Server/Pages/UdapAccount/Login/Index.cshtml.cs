#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Udap.UI.Pages;
using Udap.UI.Pages.Account.Login;
using Udap.UI.Services;

namespace Udap.Auth.Server.Pages.UdapAccount.Login;

/// <summary>
/// SecuredControls Auth sign-in (LoginUrl /udapaccount/login). When the authorize request names an upstream
/// identity provider (UDAP Tiered OAuth <c>idp</c>), the page hands sign-in to it. The logic is Udap.UI's
/// <see cref="IUdapLoginService"/>; this page only decides how it looks.
/// </summary>
[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly IUdapLoginService _login;

    public Index(IUdapLoginService login, IOptions<TestAccountOptions>? testAccounts = null)
    {
        _login = login;
        TestAccounts = testAccounts?.Value?.Accounts ?? [];
    }

    public UdapLoginContext View { get; private set; } = new();

    public IReadOnlyList<TestAccount> TestAccounts { get; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    /// <summary>The UDAP Tiered OAuth provider, when the request carries an <c>idp</c> to hand sign-in to.</summary>
    public UdapExternalProvider? TieredProvider =>
        View.ExternalProviders.FirstOrDefault(p => p.IsTieredOAuth && !string.IsNullOrEmpty(p.TieredOAuthIdp));

    public IEnumerable<UdapExternalProvider> OtherProviders =>
        View.ExternalProviders.Where(p => !p.IsTieredOAuth && !string.IsNullOrWhiteSpace(p.DisplayName));

    public string? AppName => View.Client switch
    {
        null => null,
        { ClientName: { Length: > 0 } name } => name,
        var client => client.ClientId
    };

    public async Task<IActionResult> OnGet(string? returnUrl)
    {
        await BuildModelAsync(returnUrl);

        if (View.IsExternalLoginOnly)
        {
            // only one way to sign in and it's an external provider
            return RedirectToPage("/UdapTieredLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        if (Input.Button != "login")
        {
            return this.ToActionResult(await _login.CancelAsync(HttpContext, Input.ReturnUrl));
        }

        if (ModelState.IsValid)
        {
            var result = await _login.SignInLocalAsync(HttpContext, Input.Username!, Input.Password!, Input.RememberLogin, Input.ReturnUrl);
            if (!result.IsShowPage)
            {
                return this.ToActionResult(result);
            }

            ModelState.AddModelError(string.Empty, "That username and password don't match. Check them and try again.");
        }

        var username = Input.Username;
        await BuildModelAsync(Input.ReturnUrl);
        Input.Username = username;
        return Page();
    }

    private async Task BuildModelAsync(string? returnUrl)
    {
        View = await _login.BuildLoginContextAsync(HttpContext, returnUrl);
        Input = new InputModel { ReturnUrl = returnUrl, Username = View.LoginHint };
    }

    public static string HostOf(string? idp) =>
        Uri.TryCreate(idp, UriKind.Absolute, out var uri) ? uri.Host : idp ?? string.Empty;

    public class InputModel
    {
        [Required(ErrorMessage = "Enter your username.")]
        [Display(Name = "Username")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "Enter your password.")]
        [Display(Name = "Password")]
        public string? Password { get; set; }

        public bool RememberLogin { get; set; }

        public string? ReturnUrl { get; set; }

        public string? Button { get; set; }
    }
}
