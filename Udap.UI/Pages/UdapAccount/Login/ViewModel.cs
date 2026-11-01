using Udap.Server.Security.Authentication.TieredOAuth;
using Udap.UI.Pages.Account.Login;

namespace Udap.UI.Pages.UdapAccount.Login;

public class ViewModel
{
    public bool AllowRememberLogin { get; set; } = true;
    public bool EnableLocalLogin { get; set; } = true;

    /// <summary>
    /// Test credentials offered as fill-in buttons on the login form. Empty hides the helper.
    /// </summary>
    public IEnumerable<TestAccount> TestAccounts { get; set; } = Enumerable.Empty<TestAccount>();

    public IEnumerable<ExternalProvider> ExternalProviders { get; set; } = Enumerable.Empty<ExternalProvider>();
    
    public IEnumerable<ExternalProvider> VisibleExternalProviders => 
        ExternalProviders.Where(x => 
            !string.IsNullOrWhiteSpace(x.DisplayName) &&
            x.AuthenticationScheme != TieredOAuthAuthenticationDefaults.AuthenticationScheme);
    
    public ExternalProvider? TieredProvider => 
        ExternalProviders.SingleOrDefault(p =>
            !string.IsNullOrEmpty(p.TieredOAuthIdp) &&
            p.AuthenticationScheme == TieredOAuthAuthenticationDefaults.AuthenticationScheme);

    
    public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders.Count() == 1;
    public string? ExternalLoginScheme => ExternalProviders.SingleOrDefault()?.AuthenticationScheme;
        
    public class ExternalProvider
    {
        public string? DisplayName { get; set; }
        public string? AuthenticationScheme { get; set; }

        public string? ReturnUrl { get; set; }
        public string? TieredOAuthIdp { get; set; }
    }
}