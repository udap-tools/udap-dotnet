#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using UdapEd.Client.Services;
using UdapEd.Client.Shared;
using UdapEd.Shared.Model;

namespace UdapEd.Client.Pages;

public partial class UdapRegistration
{
    [CascadingParameter]
    public CascadingAppState AppState { get; set; } = null!;

    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] RegisterService MetadataService { get; set; } = null!;

    [Inject] NavigationManager NavigationManager { get; set; } = null!;

    private string SoftwareStatementBeforeEncoding
    {
        get => AppState.SoftwareStatementBeforeEncoding;
        set => AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), value, false);
    }

    private string? _registrationResult;
    private string? RegistrationResult
    {
        get
        {
            if (!string.IsNullOrEmpty(_registrationResult))
            {
                return _registrationResult;
            }

            if (AppState.UdapRegistrationRequest == null)
            {
                return _registrationResult;
            }

            return JsonSerializer.Serialize(AppState
                .RegistrationDocument, new JsonSerializerOptions { WriteIndented = true });
        }
        set => _registrationResult = value;
    }


    private Oauth2FlowEnum Oauth2Flow
    {
        get => AppState.Oauth2Flow;
        set => AppState.SetProperty(this, nameof(AppState.Oauth2Flow), value);
    }

    private string _requestBody = string.Empty;

    private string RequestBody
    {
        get
        {
            if (!string.IsNullOrEmpty(_requestBody))
            {
                return _requestBody;
            }

            if (AppState.UdapRegistrationRequest == null)
            {
                return _requestBody;
            }

            return JsonSerializer.Serialize(AppState
                    .UdapRegistrationRequest, new JsonSerializerOptions { WriteIndented = true });
        }
        set => _requestBody = value;
    }

   
    private async Task BuildRawSoftwareStatement()
    {
        try
        {
            SoftwareStatementBeforeEncoding = "Loading ...";
            await Task.Delay(50);

            var request = new BuildSoftwareStatementRequest
            {
                MetadataUrl = AppState.MetadataUrl,
                Audience = AppState.UdapMetadata?.RegistrationEndpoint,
                Oauth2Flow = AppState.Oauth2Flow,
                RedirectUri = $"{NavigationManager.BaseUri}udapBusinessToBusiness"
            };

            SoftwareStatementBeforeEncoding = await MetadataService.BuildSoftwareStatement(request);
            AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), SoftwareStatementBeforeEncoding);
        }
        catch (Exception ex)
        {
            SoftwareStatementBeforeEncoding = ex.Message;
            ResetSoftwareStatement();
        }
    }

    private void ResetSoftwareStatement()
    {
        SoftwareStatementBeforeEncoding = string.Empty;
        AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), string.Empty);
        RequestBody = string.Empty;
        AppState.SetProperty(this, nameof(AppState.UdapRegistrationRequest), null);
        RegistrationResult = string.Empty;
        AppState.SetProperty(this, nameof(AppState.RegistrationDocument), null);
    }

    private async Task BuildRequestBody()
    {
        RequestBody = "Loading ...";
        await Task.Delay(50);

        var request = new BuildSoftwareStatementRequest
        {
            MetadataUrl = AppState.MetadataUrl,
            Audience = AppState.UdapMetadata?.RegistrationEndpoint,
            Oauth2Flow = AppState.Oauth2Flow,
            RedirectUri = $"{NavigationManager.BaseUri}udapBusinessToBusiness"
        };

        var registerRequest = await MetadataService.BuildRequestBody(request);
        AppState.SetProperty(this, nameof(AppState.UdapRegistrationRequest), registerRequest);
        
        RequestBody = JsonSerializer.Serialize(
            registerRequest,
            new JsonSerializerOptions { WriteIndented = true });
    }

    private async Task PerformRegistration()
    {
        RegistrationResult = "Loading ...";
        await Task.Delay(50);

        var registrationRequest = new RegistrationRequest
        {
            RegistrationEndpoint = AppState.UdapMetadata?.RegistrationEndpoint,
            UdapRegisterRequest = AppState.UdapRegistrationRequest
        };

        var result = await MetadataService.Register(registrationRequest);
        
        if (result is { Success: true })
        {
            RegistrationResult = JsonSerializer.Serialize(
                result,
                new JsonSerializerOptions { WriteIndented = true });
            
            AppState.SetProperty(this, nameof(AppState.RegistrationDocument), result.Document);
        }
        else
        {
            RegistrationResult = result?.ErrorMessage ?? string .Empty;
            AppState.SetProperty(this, nameof(AppState.RegistrationDocument), null);
        }
    }
    
    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
