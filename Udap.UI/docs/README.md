# Udap.UI

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 Nuget Package: [Udap.UI](https://www.nuget.org/packages/Udap.UI)

This package provides Razor Pages and static assets for the authentication and consent UI used with Duende IdentityServer and UDAP. It includes pages for login, logout, consent, device authorization, CIBA, and grant management, along with support for UDAP Tiered OAuth flows.

Include this package in a server that already includes the `Udap.Server` package.

## Bring your own UI

The pages are a reference look. Their protocol logic lives in services you can call from your own
pages, so a host can replace the markup and styling entirely without copying page models:

```csharp
builder.Services.AddUdapUI(options =>
{
    options.Login.AllowRememberLogin = false;
    options.Logout.ShowLogoutPrompt = false;
});

// Optional: sign users in against your own identity store instead of Duende TestUsers.
builder.Services.AddTransient<IUdapUserStore, MyUserStore>();
```

| Service | Use it for |
|---|---|
| `IUdapLoginService` | Login page model (providers, UDAP `idp` hint, local-login rules), credential sign-in, cancel, and `SignInUserAsync` for an already-verified user (passkey, registration). |
| `IUdapExternalLoginService` | Tiered OAuth and external OIDC challenge properties; the shared callback that finds or provisions the user and signs them in. |
| `IUdapLogoutService` | Logout prompt decision, local sign-out with the upstream sign-out scheme, logged-out page context. |
| `IUdapConsentService` | Consent page context and recording the user's decision. `UdapScopeListBuilder` builds the permission list for device and CIBA screens too. |
| `IUdapUserStore` | The user store behind login. Defaults to `TestUserStoreAdapter` over Duende's `TestUserStore`. |

Service calls return a `UdapInteractionResult` (redirect, native-client redirect, or show the page
with an error); `this.ToActionResult(result)` converts the redirecting kinds in a `PageModel`.

The built-in pages use these services too, and still work when `AddUdapUI()` is not called.

## Plain-language permissions

`UdapScopeLanguage.Describe(scope)` words an OIDC, SMART App Launch (v1/v2) or UDAP scope for the person
granting consent, e.g. `patient/MedicationDispense.rs` reads "Your filled prescriptions: The app can look
at and search the medicines pharmacies have filled for you." It builds the wording from the scope's parts
(context, FHIR resource type, permissions), so a whole SMART scope catalog reads well without per-scope
descriptions, and flags scopes that can change records or reach beyond the patient's own records. Its
`Technical` text gives the breakdown for a "Plain language" / "Technical" switch. The example servers
(SecuredControls Auth, SecuredControls Identity) show both.
