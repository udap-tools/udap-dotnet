using Udap.Server.Security.Authentication.TieredOAuth;

namespace Udap.Auth.Server.Pages.UdapAccount.Login;

public class ViewModel
{
    public bool AllowRememberLogin { get; set; } = true;
    public bool EnableLocalLogin { get; set; } = true;

    public IEnumerable<ExternalProvider> ExternalProviders { get; set; } = Enumerable.Empty<ExternalProvider>();
    
    public IEnumerable<ExternalProvider> VisibleExternalProviders => 
        ExternalProviders.Where(x => 
            !string.IsNullOrWhiteSpace(x.DisplayName) &&
            x.AuthenticationScheme != TieredOAuthAuthenticationDefaults.AuthenticationScheme);
    
    public ExternalProvider? TieredProvider => 
        ExternalProviders.SingleOrDefault(p =>
            p.AuthenticationScheme == TieredOAuthAuthenticationDefaults.AuthenticationScheme);

    
    public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders.Count() == 1;
    public string? ExternalLoginScheme => ExternalProviders.SingleOrDefault()?.AuthenticationScheme;
        
    public class ExternalProvider
    {
        public string? DisplayName { get; set; }
        public string? AuthenticationScheme { get; set; }

        public string? ReturnUrl { get; set; }
    }
}