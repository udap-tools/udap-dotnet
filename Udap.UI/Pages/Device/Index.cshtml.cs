using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.UI.Pages.Consent;
using Udap.UI.Options;
using Udap.UI.Services;

namespace Udap.UI.Pages.Device;

[SecurityHeaders]
[Authorize]
public class Index : PageModel
{
    private readonly IDeviceFlowInteractionService _interaction;
    private readonly IEventService _events;
    private readonly IOptions<IdentityServerOptions> _options;
    private readonly ILogger<Index> _logger;

    public Index(
        IDeviceFlowInteractionService interaction,
        IEventService eventService,
        IOptions<IdentityServerOptions> options,
        ILogger<Index> logger)
    {
        _interaction = interaction;
        _events = eventService;
        _options = options;
        _logger = logger;
    }

    public ViewModel View { get; set; }

    [BindProperty]
    public InputModel Input { get; set; }

    public async Task<IActionResult> OnGet(string userCode)
    {
        if (String.IsNullOrWhiteSpace(userCode))
        {
            View = new ViewModel();
            Input = new InputModel();
            return Page();
        }

        View = await BuildViewModelAsync(userCode);
        if (View == null)
        {
            ModelState.AddModelError("", DeviceOptions.InvalidUserCode);
            View = new ViewModel();
            Input = new InputModel();
            return Page();
        }

        Input = new InputModel { 
            UserCode = userCode,
        };

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        var request = await _interaction.GetAuthorizationContextAsync(Input.UserCode, HttpContext.RequestAborted);
        if (request == null) return RedirectToPage("/Home/Error/Index");

        ConsentResponse grantedConsent = null;

        // user clicked 'no' - send back the standard 'access_denied' response
        if (Input.Button == "no")
        {
            grantedConsent = new ConsentResponse
            {
                Error = InteractionError.AccessDenied
            };

            // emit event
            await _events.RaiseAsync(new ConsentDeniedEvent(User.GetSubjectId(), request.Client.ClientId, request.ValidatedResources.RawScopeValues), HttpContext.RequestAborted);
        }
        // user clicked 'yes' - validate the data
        else if (Input.Button == "yes")
        {
            // if the user consented to some scope, build the response model
            if (Input.ScopesConsented != null && Input.ScopesConsented.Any())
            {
                var scopes = Input.ScopesConsented;
                if (ConsentOptions.EnableOfflineAccess == false)
                {
                    scopes = scopes.Where(x => x != Duende.IdentityServer.IdentityServerConstants.StandardScopes.OfflineAccess);
                }

                grantedConsent = new ConsentResponse
                {
                    RememberConsent = Input.RememberConsent,
                    ScopesValuesConsented = scopes.ToArray(),
                    Description = Input.Description
                };

                // emit event
                await _events.RaiseAsync(new ConsentGrantedEvent(User.GetSubjectId(), request.Client.ClientId, request.ValidatedResources.RawScopeValues, grantedConsent.ScopesValuesConsented, grantedConsent.RememberConsent), HttpContext.RequestAborted);
            }
            else
            {
                ModelState.AddModelError("", ConsentOptions.MustChooseOneErrorMessage);
            }
        }
        else
        {
            ModelState.AddModelError("", ConsentOptions.InvalidSelectionErrorMessage);
        }

        if (grantedConsent != null)
        {
            // communicate outcome of consent back to identityserver
            await _interaction.HandleRequestAsync(Input.UserCode, grantedConsent, HttpContext.RequestAborted);

            // indicate that's it ok to redirect back to authorization endpoint
            return RedirectToPage("/Device/Success");
        }

        // we need to redisplay the consent UI
        View = await BuildViewModelAsync(Input.UserCode, Input);
        return Page();
    }


    private async Task<ViewModel> BuildViewModelAsync(string userCode, InputModel model = null)
    {
        var request = await _interaction.GetAuthorizationContextAsync(userCode, HttpContext.RequestAborted);
        if (request != null)
        {
            return CreateConsentViewModel(model, request);
        }

        return null;
    }

    private ViewModel CreateConsentViewModel(InputModel model, DeviceFlowAuthorizationRequest request)
    {
        var options = new UdapUIConsentOptions
        {
            EnableOfflineAccess = DeviceOptions.EnableOfflineAccess,
            OfflineAccessDisplayName = DeviceOptions.OfflineAccessDisplayName,
            OfflineAccessDescription = DeviceOptions.OfflineAccessDescription
        };

        var scopes = UdapScopeListBuilder.Build(request.ValidatedResources, null, model == null ? null : model.ScopesConsented ?? Array.Empty<string>(), options);

        return new ViewModel
        {
            ClientName = request.Client.ClientName ?? request.Client.ClientId,
            ClientUrl = request.Client.ClientUri,
            ClientLogoUrl = request.Client.LogoUri,
            AllowRememberConsent = request.Client.AllowRememberConsent,
            IdentityScopes = scopes.IdentityScopes.Select(ToViewModel).ToArray(),
            ApiScopes = scopes.ApiScopes.Select(ToViewModel).ToArray()
        };
    }

    private static ScopeViewModel ToViewModel(UdapScope scope)
    {
        return new ScopeViewModel
        {
            Value = scope.Value,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            Emphasize = scope.Emphasize,
            Required = scope.Required,
            Checked = scope.Checked
        };
    }
}
