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
using Udap.Model;
using UdapClient.Client.Services;
using UdapClient.Shared;

namespace UdapClient.Client.Pages;

public partial class UdapDiscovery
{
    [Inject] private HttpClient _http { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }

    [Inject] private UdapClientState UdapClientState { get; set; } = new UdapClientState();
    [Inject] private ProfileService ProfileService { get; set; }
    [Inject] MetadataService MetadataService { get; set; }

    private string Result { get; set; } = "";

    private async Task GetMetadata()
    {
        try
        {
            Result = "...";
            await Task.Delay(250);

            UdapClientState.UdapMetadata = 
                await MetadataService.GetMetadata(UdapClientState.MetadataUrl);
            await ProfileService.SaveUdapClientState(UdapClientState);

            Result = JsonSerializer.Serialize<UdapMetadata>(
                UdapClientState.UdapMetadata,
                new JsonSerializerOptions { WriteIndented = true });
        }
        catch (Exception ex)
        {
            Result = ex.Message;
        }
    }

    protected override async Task OnInitializedAsync()
    {
        if (!UdapClientState.IsLocalStorageInit())
        {
            UdapClientState = await ProfileService.GetUdapClientState();
        }

        Result = UdapClientState.UdapMetadata.AsJson();
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
