#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using UdapClient.Client.Services;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Pages;

public partial class UdapRegistration
{
    [Inject] private HttpClient _http { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] UdapClientState UdapClientState { get; set; } = new UdapClientState();
    [Inject] MetadataService MetadataService { get; set; }

    private string SoftwareStatementBeforeEncoding { get; set; } = "";
    private string RequestBody { get; set; }

    private async Task Build()
    {
        try
        {
            var request = new BuildSoftwareStatementRequest();
            request.MetadataUrl = UdapClientState.MetadataUrl;
            
            //TODO Get from User:: Dialog or form
            request.Password = "udap-test";

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
        request.Password = "udap-test";

        RequestBody = await MetadataService.BuildRequestBody(request);
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

    
}
