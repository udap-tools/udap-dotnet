using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Udap.UI.Services;

namespace Udap.UI.Pages.Account.Login;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly IServiceProvider _services;
    private readonly IReadOnlyList<TestAccount> _testAccounts;

    public ViewModel View { get; set; }

    [BindProperty]
    public InputModel Input { get; set; }

    public Index(IServiceProvider services, IOptions<TestAccountOptions>? testAccounts = null)
    {
        // the login logic lives in IUdapLoginService; plug in your own identity store by registering an IUdapUserStore
        _services = services;
        _testAccounts = testAccounts?.Value?.Accounts ?? new List<TestAccount>();
    }

    private IUdapLoginService LoginService => _services.GetUdapLoginService();

    public async Task<IActionResult> OnGet(string returnUrl)
    {
        await BuildModelAsync(returnUrl);

        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage("/ExternalLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        if (Input == null) throw new InvalidOperationException("Input is null");

        // the user clicked the "cancel" button
        if (Input.Button != "login")
        {
            return this.ToActionResult(await LoginService.CancelAsync(HttpContext, Input.ReturnUrl));
        }

        if (ModelState.IsValid)
        {
            var result = await LoginService.SignInLocalAsync(HttpContext, Input.Username, Input.Password, Input.RememberLogin, Input.ReturnUrl);
            if (!result.IsShowPage)
            {
                return this.ToActionResult(result);
            }

            ModelState.AddModelError(string.Empty, result.Error ?? string.Empty);
        }

        // something went wrong, show form with error
        await BuildModelAsync(Input.ReturnUrl);
        return Page();
    }

    private async Task BuildModelAsync(string returnUrl)
    {
        var context = await LoginService.BuildLoginContextAsync(HttpContext, returnUrl);

        Input = new InputModel
        {
            ReturnUrl = returnUrl,
            Username = context.LoginHint ?? string.Empty
        };

        View = new ViewModel
        {
            AllowRememberLogin = context.AllowRememberLogin,
            EnableLocalLogin = context.EnableLocalLogin,
            ExternalProviders = context.ExternalProviders
                .Select(x => new ViewModel.ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.AuthenticationScheme,
                    ReturnUrl = x.ReturnUrl
                })
                .ToArray(),
            TestAccounts = _testAccounts
        };
    }
}
