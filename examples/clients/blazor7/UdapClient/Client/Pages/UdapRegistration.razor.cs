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
using MudBlazor;
using UdapClient.Client.Services;
using UdapClient.Client.Shared;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Pages;

public partial class UdapRegistration
{
    [CascadingParameter]
    public CascadingAppState AppState { get; set; } = null!;

    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] RegisterService MetadataService { get; set; } = null!;
    
    private string SoftwareStatementBeforeEncoding
    {
        get => AppState.SoftwareStatementBeforeEncoding;
        set => AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), value, false);
    }

    private string _registrationResult;
    private string RegistrationResult
    {
        get
        {
            if (AppState.RegistrationRequest == null)
            {
                return _registrationResult;
            }

            return JsonSerializer.Serialize(AppState
                .RegistrationDocument, new JsonSerializerOptions { WriteIndented = true });
        }
        set => _registrationResult = value;
    }

   
    private Oauth2FlowEnum Oauth2Flow { get; set; }

    private async Task SetOauth2FlowProperty(ChangeEventArgs args)
    {
        AppState.SetProperty(this, nameof(AppState.UdapMetadata), args.Value);
    }

    private string _requestBody = string.Empty;

    private string RequestBody
    {
        get
        {
            if (AppState.RegistrationRequest == null)
            {
                return _requestBody;
            }

            return JsonSerializer.Serialize(AppState
                    .RegistrationRequest, new JsonSerializerOptions { WriteIndented = true });
        }
        set => _requestBody = value;
    }

   
    private async Task BuildRawSoftwareStatement()
    {
        try
        {
            var request = new BuildSoftwareStatementRequest();
            request.MetadataUrl = AppState.MetadataUrl;
            request.Audience = AppState.UdapMetadata?.RegistrationEndpoint;
            request.Oauth2Flow = AppState.Oauth2Flow;


            SoftwareStatementBeforeEncoding = await MetadataService.BuildSoftwareStatement(request);
            AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), SoftwareStatementBeforeEncoding);
           
        }
        catch (Exception ex)
        {
            SoftwareStatementBeforeEncoding = ex.Message;
            await ResetSoftwareStatment();
        }
    }

    private async Task ResetSoftwareStatment()
    {
        SoftwareStatementBeforeEncoding = string.Empty;
        AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), string.Empty);
        RequestBody = string.Empty;
        AppState.SetProperty(this, nameof(AppState.RegistrationRequest), null);
        RegistrationResult = string.Empty;
        AppState.SetProperty(this, nameof(AppState.RegistrationDocument), null);
    }

    private async Task BuildRequestBody()
    {
        var request = new BuildSoftwareStatementRequest();
        request.MetadataUrl = AppState.MetadataUrl;
        request.Audience = AppState.UdapMetadata?.RegistrationEndpoint;
        request.Oauth2Flow = AppState.Oauth2Flow;

        var registerRequest = await MetadataService.BuildRequestBody(request);
        AppState.SetProperty(this, nameof(AppState.RegistrationRequest), registerRequest);
        
        RequestBody = JsonSerializer.Serialize(
            registerRequest,
            new JsonSerializerOptions { WriteIndented = true });
        
    }

    private async Task PerformRegistration()
    {
        var registrationRequest = new RegistrationRequest
        {
            RegistrationEndpoint = AppState.UdapMetadata?.RegistrationEndpoint,
            UdapRegisterRequest = AppState.RegistrationRequest
        };

        var result = await MetadataService.Register(registrationRequest);
        
        if (result != null && result.Success)
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
