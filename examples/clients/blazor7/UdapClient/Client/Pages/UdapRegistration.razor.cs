using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

namespace UdapClient.Client.Pages;

public partial class UdapRegistration
{
    [Inject] private HttpClient _http { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }

    private string metadataUrl = "https://fhirlabs.net/fhir/r4/.well-known/udap";
    private string Result { get; set; } = "";

    private async Task Build()
    {
        try
        {
            Result = "stuff";
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
