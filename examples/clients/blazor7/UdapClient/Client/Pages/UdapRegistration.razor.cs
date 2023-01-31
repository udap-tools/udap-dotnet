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
    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] UdapClientState State { get; set; }
    [Inject] RegisterService MetadataService { get; set; }
    [Inject] private ProfileService ProfileService { get; set; }

    private string SoftwareStatementBeforeEncoding { get; set; } = "";
    private string RequestBody { get; set; }
    private string RegistrationResult { get; set; }
    private string Password { get; set; } = "udap-test";
    public Color CertLoadedColor { get; set; } = Color.Error;

    bool isShow;
    InputType PasswordInput = InputType.Password;
    string PasswordInputIcon = Icons.Material.Filled.VisibilityOff;

    void ShowPassword()
    {
        if (isShow)
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
        // if (!State.IsLocalStorageInit)
        // {
        //     State = await ProfileService.GetUdapClientState();
        // }

        SoftwareStatementBeforeEncoding = State.SoftwareStatementBeforeEncoding;
        
        RequestBody = JsonSerializer.Serialize(
            State.RegistrationRequest,
            new JsonSerializerOptions { WriteIndented = true });

        RegistrationResult = RegistrationResult = JsonSerializer.Serialize(
            State.RegistrationDocument,
            new JsonSerializerOptions { WriteIndented = true });

        SetCertLoadedColor(await MetadataService.IsCertLoaded(Password));
    }

    private void SetCertLoadedColor(CertLoadedEnum isCertLoaded)
    {
        switch (isCertLoaded)
        {
            case CertLoadedEnum.Negative:
                CertLoadedColor = Color.Error;
                break;
            case CertLoadedEnum.Positive:
                CertLoadedColor = Color.Success;
                break;
            case CertLoadedEnum.InvalidPassword:
                CertLoadedColor = Color.Warning;
                break;
            default:
                CertLoadedColor = Color.Error;
                break;
        }
    }

    private async Task BuildRawSoftwareStatement()
    {
        try
        {
            var request = new BuildSoftwareStatementRequest();
            request.MetadataUrl = State.MetadataUrl;
            request.Audience = State.UdapMetadata.RegistrationEndpoint;
            request.Password = Password;
            request.Oauth2Flow = State.Oauth2Flow;


            SoftwareStatementBeforeEncoding = await MetadataService.BuildSoftwareStatement(request);
            State.SoftwareStatementBeforeEncoding = SoftwareStatementBeforeEncoding;

            if (CertLoadedColor != Color.Success)
            {
                SetCertLoadedColor(await MetadataService.IsCertLoaded(Password));
            }
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
        State.SoftwareStatementBeforeEncoding = string.Empty;
        RequestBody = string.Empty;
        State.RegistrationRequest = null;
        RegistrationResult = string.Empty;
        State.RegistrationDocument = null;
        await ProfileService.SaveUdapClientState(State);
    }

    private async Task BuildRequestBody()
    {
        var request = new BuildSoftwareStatementRequest();
        request.MetadataUrl = State.MetadataUrl;
        request.Audience = State.UdapMetadata.RegistrationEndpoint;
        request.Password = Password;
        request.Oauth2Flow = State.Oauth2Flow;

        State.RegistrationRequest = await MetadataService.BuildRequestBody(request);

        RequestBody = JsonSerializer.Serialize(
            State.RegistrationRequest,
            new JsonSerializerOptions { WriteIndented = true });

        await ProfileService.SaveUdapClientState(State);

        if (CertLoadedColor != Color.Success)
        {
            SetCertLoadedColor(await MetadataService.IsCertLoaded(Password));
        }
    }

    private async Task PerformRegistration()
    {
        var registrationRequest = new RegistrationRequest
        {
            RegistrationEndpoint = State.UdapMetadata.RegistrationEndpoint,
            UdapRegisterRequest = State.RegistrationRequest
        };

        var result = await MetadataService.Register(registrationRequest);
        
        if (result != null && result.Success)
        {
            RegistrationResult = JsonSerializer.Serialize(
                result,
                new JsonSerializerOptions { WriteIndented = true });

            State.RegistrationDocument = result.Document;
        }
        else
        {
            RegistrationResult = result?.ErrorMessage ?? string .Empty;
            State.RegistrationDocument = null;
        }
        

        await ProfileService.SaveUdapClientState(State);
    }

    private async Task UploadFilesAsync(InputFileChangeEventArgs e)
    {
        long maxFileSize = 1024 * 10;

        var uploadStream = await new StreamContent(e.File.OpenReadStream(maxFileSize)).ReadAsStreamAsync();
        var ms = new MemoryStream();
        await uploadStream.CopyToAsync(ms);
        var certBytes = ms.ToArray();

        await MetadataService.UploadClientCert(Convert.ToBase64String(certBytes));

        SetCertLoadedColor(await MetadataService.IsCertLoaded(Password));
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
