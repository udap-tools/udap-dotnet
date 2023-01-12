using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Udap.Model;
using UdapClient.Client.Services;

namespace UdapClient.Client.Pages;

public partial class UdapDiscovery
{
    [Inject] private HttpClient _http { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }

    [Inject] UdapClientState UdapClientState { get; set; } = new UdapClientState();


    private string Result { get; set; } = "";

    private async Task GetMetadata()
    {
        try
        {
            Result = await _http.GetStringAsync(UdapClientState.MetadataUrl);

            var _wellKnownUdap = System.Text.Json.JsonSerializer.Deserialize<UdapMetadata>(Result);
        }
        catch (Exception ex)
        {
            Result = ex.Message;
        }
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
