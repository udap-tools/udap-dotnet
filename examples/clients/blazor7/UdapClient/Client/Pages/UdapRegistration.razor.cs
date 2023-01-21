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
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using MudBlazor;
using UdapClient.Client.Services;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Pages;

public partial class UdapRegistration
{
    [Inject] private HttpClient _http { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] UdapClientState UdapClientState { get; set; } = new UdapClientState();
    [Inject] MetadataService MetadataService { get; set; }
    [Inject] private ProfileService ProfileService { get; set; }

    private string SoftwareStatementBeforeEncoding { get; set; } = "";
    private string RequestBody { get; set; }
    private string RegistrationResult { get; set; }
    private string Password { get; set; } = "udap-test";
    private Oauth2FlowEnum Oauth2Flow { get; set; } = Oauth2FlowEnum.client_credentials;
    
    bool isShow;
    InputType PasswordInput = InputType.Password;
    string PasswordInputIcon = Icons.Material.Filled.VisibilityOff;

    void ButtonTestclick()
    {
        if(isShow)
        {
            isShow = false;
            PasswordInputIcon = Icons.Material.Filled.VisibilityOff;
            PasswordInput = InputType.Password;
        }
        else
        {
            isShow = true;
            PasswordInputIcon = Icons.Material.Filled.Visibility;
            PasswordInput = InputType.Text;
        }
    }

    protected override async Task OnInitializedAsync()
    {
        if (!UdapClientState.IsLocalStorageInit())
        {
            UdapClientState = await ProfileService.GetUdapClientState();
        }
    }

    private async Task Build()
    {
        try
        {
            var request = new BuildSoftwareStatementRequest();
            request.MetadataUrl = UdapClientState.MetadataUrl;
            request.Audience = UdapClientState.UdapMetadata.RegistrationEndpoint;
            request.Password = Password;

            SoftwareStatementBeforeEncoding = await MetadataService.BuildSoftwareStatement(request);
            UdapClientState.SoftwareStatementBeforeEncoding = SoftwareStatementBeforeEncoding;
        }
        catch (Exception ex)
        {
            SoftwareStatementBeforeEncoding = ex.Message;
        }
    }

    private async Task BuildRequestBody()
    {
        var request = new BuildSoftwareStatementRequest();
        request.MetadataUrl = UdapClientState.MetadataUrl;
        request.Audience = UdapClientState.UdapMetadata.RegistrationEndpoint;
        request.Password = Password;

        UdapClientState.RegistrationRequest = await MetadataService.BuildRequestBody(request);

        RequestBody = JsonSerializer.Serialize(
            UdapClientState.RegistrationRequest,
            new JsonSerializerOptions { WriteIndented = true });
    }

    private async Task PerformRegistration()
    {
        var registrationRequest = new RegistrationRequest
        {
            RegistrationEndpoint = UdapClientState.UdapMetadata.RegistrationEndpoint,
            UdapRegisterRequest = UdapClientState.RegistrationRequest
        };

        var result = await MetadataService.Register(registrationRequest);
        UdapClientState.AccessCode = result;

        RegistrationResult = JsonSerializer.Serialize(
            result,
            new JsonSerializerOptions { WriteIndented = true });
    }

    private async Task UploadFilesAsync(InputFileChangeEventArgs e)
    {
        long maxFileSize = 1024 * 10;

        var uploadStream = await new StreamContent(e.File.OpenReadStream(maxFileSize)).ReadAsStreamAsync();
        var ms = new MemoryStream();
        await uploadStream.CopyToAsync(ms);
        var certBytes = ms.ToArray();

        await MetadataService.UploadClientCert(Convert.ToBase64String(certBytes));
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
    
    public enum Oauth2FlowEnum { authorization_code, client_credentials }

}
