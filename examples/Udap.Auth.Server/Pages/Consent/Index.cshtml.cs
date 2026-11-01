#region (c) 2026 Joseph Shook. All rights reserved.
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
using Udap.UI.Pages;
using Udap.UI.Services;

namespace Udap.Auth.Server.Pages.Consent;

/// <summary>
/// "Allow this app?" (/consent). The logic is Udap.UI's <see cref="IUdapConsentService"/>; this page decides
/// how it looks. The form posts the standard Udap.UI field names (Input.ReturnUrl, Input.ScopesConsented,
/// Input.Button, Input.RememberConsent).
/// </summary>
[Authorize]
[SecurityHeaders]
public class Index : PageModel
{
    private readonly IUdapConsentService _consent;

    public Index(IUdapConsentService consent)
    {
        _consent = consent;
    }

    public UdapConsentContext? View { get; private set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public async Task<IActionResult> OnGet(string? returnUrl)
    {
        View = await _consent.BuildConsentContextAsync(HttpContext, returnUrl);
        if (View == null)
        {
            return RedirectToPage("/Home/Error/Index");
        }

        Input = new InputModel { ReturnUrl = returnUrl };
        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        var result = await _consent.ProcessConsentAsync(
            HttpContext, Input.ReturnUrl, Input.Button, Input.ScopesConsented, Input.RememberConsent, Input.Description);

        if (result == null)
        {
            // the authorize request expired or was already answered
            return RedirectToPage("/Home/Error/Index");
        }

        if (!result.IsShowPage)
        {
            return this.ToActionResult(result);
        }

        ModelState.AddModelError(string.Empty, $"{result.Error}.");
        View = await _consent.BuildConsentContextAsync(HttpContext, Input.ReturnUrl, Input.ScopesConsented ?? []);
        return View == null ? RedirectToPage("/Home/Error/Index") : Page();
    }

    public class InputModel
    {
        public string? Button { get; set; }
        public IEnumerable<string>? ScopesConsented { get; set; }
        public bool RememberConsent { get; set; } = true;
        public string? ReturnUrl { get; set; }
        public string? Description { get; set; }
    }
}
