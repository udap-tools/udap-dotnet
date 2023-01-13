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

    private string Result { get; set; } = "";

    private async Task GetMetadata()
    {
        try
        {
            Result = "...";
            await Task.Delay(250);

            Result = await _http.GetStringAsync(UdapClientState?.MetadataUrl);

            UdapClientState.UdapMetadata = System.Text.Json.JsonSerializer.Deserialize<UdapMetadata>(Result);
            await ProfileService.SaveUdapClientState(UdapClientState);
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
