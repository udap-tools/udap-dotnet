using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.UI.Services;

namespace Udap.UI.Pages.Consent;

[Authorize]
[SecurityHeaders]
public class Index : PageModel
{
    private readonly IServiceProvider _services;

    public Index(IServiceProvider services)
    {
        _services = services;
    }

    public ViewModel View { get; set; }
        
    [BindProperty]
    public InputModel Input { get; set; }

    private IUdapConsentService ConsentService => _services.GetUdapConsentService();

    public async Task<IActionResult> OnGet(string returnUrl)
    {
        View = await BuildViewModelAsync(returnUrl);
        if (View == null)
        {
            return RedirectToPage("/Home/Error/Index");
        }

        Input = new InputModel
        {
            ReturnUrl = returnUrl,
        };

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        var result = await ConsentService.ProcessConsentAsync(
            HttpContext,
            Input?.ReturnUrl,
            Input?.Button,
            Input?.ScopesConsented,
            Input?.RememberConsent ?? false,
            Input?.Description);

        // the authorize request is no longer valid
        if (result == null) return RedirectToPage("/Home/Error/Index");

        if (!result.IsShowPage)
        {
            return this.ToActionResult(result);
        }

        // we need to redisplay the consent UI
        ModelState.AddModelError("", result.Error ?? string.Empty);
        View = await BuildViewModelAsync(Input!.ReturnUrl, Input.ScopesConsented ?? Array.Empty<string>());
        return Page();
    }

    private async Task<ViewModel> BuildViewModelAsync(string returnUrl, IEnumerable<string> scopesConsented = null)
    {
        var context = await ConsentService.BuildConsentContextAsync(HttpContext, returnUrl, scopesConsented);
        if (context == null)
        {
            return null;
        }

        return new ViewModel
        {
            ClientName = context.ClientName,
            ClientUrl = context.ClientUrl,
            ClientLogoUrl = context.ClientLogoUrl,
            AllowRememberConsent = context.AllowRememberConsent,
            IdentityScopes = context.Scopes.IdentityScopes.Select(ToViewModel).ToArray(),
            ApiScopes = context.Scopes.ApiScopes.Select(ToViewModel).ToArray()
        };
    }

    private static ScopeViewModel ToViewModel(UdapScope scope)
    {
        return new ScopeViewModel
        {
            Name = scope.Name,
            Value = scope.Value,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            Emphasize = scope.Emphasize,
            Required = scope.Required,
            Checked = scope.Checked,
            Resources = scope.Resources
                .Select(x => new ResourceViewModel { Name = x.Name, DisplayName = x.DisplayName })
                .ToArray()
        };
    }
}
