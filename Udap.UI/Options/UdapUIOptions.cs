#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.UI.Options;

/// <summary>
/// Behavior settings for the Udap.UI interaction services. Hosts that bring their own pages
/// configure these through <see cref="UdapUIServiceCollectionExtensions.AddUdapUI"/>.
/// </summary>
/// <remarks>
/// Defaults come from the legacy static option classes
/// (<c>Udap.UI.Pages.UdapAccount.Login.LoginOptions</c>, <c>Udap.UI.Pages.UdapAccount.Logout.LogoutOptions</c>,
/// <c>Udap.UI.Pages.Consent.ConsentOptions</c>) when the options are first created, so hosts that still
/// assign those statics keep their behavior. Any <c>Configure</c> delegate overrides them.
/// </remarks>
public class UdapUIOptions
{
    public UdapUILoginOptions Login { get; set; } = new();
    public UdapUILogoutOptions Logout { get; set; } = new();
    public UdapUIConsentOptions Consent { get; set; } = new();
}

public class UdapUILoginOptions
{
    public bool AllowLocalLogin { get; set; } = Pages.UdapAccount.Login.LoginOptions.AllowLocalLogin;
    public bool AllowRememberLogin { get; set; } = Pages.UdapAccount.Login.LoginOptions.AllowRememberLogin;
    public TimeSpan RememberMeLoginDuration { get; set; } = Pages.UdapAccount.Login.LoginOptions.RememberMeLoginDuration;
    public string InvalidCredentialsErrorMessage { get; set; } = Pages.UdapAccount.Login.LoginOptions.InvalidCredentialsErrorMessage;
}

public class UdapUILogoutOptions
{
    public bool ShowLogoutPrompt { get; set; } = Pages.UdapAccount.Logout.LogoutOptions.ShowLogoutPrompt;
    public bool AutomaticRedirectAfterSignOut { get; set; } = Pages.UdapAccount.Logout.LogoutOptions.AutomaticRedirectAfterSignOut;
}

public class UdapUIConsentOptions
{
    public bool EnableOfflineAccess { get; set; } = Pages.Consent.ConsentOptions.EnableOfflineAccess;
    public string OfflineAccessDisplayName { get; set; } = Pages.Consent.ConsentOptions.OfflineAccessDisplayName;
    public string OfflineAccessDescription { get; set; } = Pages.Consent.ConsentOptions.OfflineAccessDescription;
    public string MustChooseOneErrorMessage { get; set; } = Pages.Consent.ConsentOptions.MustChooseOneErrorMessage;
    public string InvalidSelectionErrorMessage { get; set; } = Pages.Consent.ConsentOptions.InvalidSelectionErrorMessage;
}
