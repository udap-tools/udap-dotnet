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

    [Inject] private UdapClientState State { get; set; } 
    [Inject] private ProfileService ProfileService { get; set; }
    [Inject] DiscoveryService MetadataService { get; set; }

    private string? Result { get; set; } = "";

    private async Task GetMetadata()
    {
        try
        {
            Result = "...";
            await Task.Delay(250);

            State.UdapMetadata = 
                await MetadataService.GetMetadata(State.MetadataUrl);
            await ProfileService.SaveUdapClientState(State);

            Result = JsonSerializer.Serialize<UdapMetadata>(
                State.UdapMetadata,
                new JsonSerializerOptions { WriteIndented = true });
        }
        catch (Exception ex)
        {
            Result = ex.Message;
        }
    }

    protected override async Task OnInitializedAsync()
    {
        // if (!State.IsLocalStorageInit)
        // {
        //     State = await ProfileService.GetUdapClientState();
        // }

        // Result = State.UdapMetadata.AsJson();
    }

    /// <summary>
    /// Method invoked after each time the component has been rendered.
    /// </summary>
    /// <param name="firstRender">
    /// Set to <c>true</c> if this is the first time <see cref="M:Microsoft.AspNetCore.Components.ComponentBase.OnAfterRender(System.Boolean)" /> has been invoked
    /// on this component instance; otherwise <c>false</c>.
    /// </param>
    /// <remarks>
    /// The <see cref="M:Microsoft.AspNetCore.Components.ComponentBase.OnAfterRender(System.Boolean)" /> and <see cref="M:Microsoft.AspNetCore.Components.ComponentBase.OnAfterRenderAsync(System.Boolean)" /> lifecycle methods
    /// are useful for performing interop, or interacting with values received from <c>@ref</c>.
    /// Use the <paramref name="firstRender" /> parameter to ensure that initialization work is only performed
    /// once.
    /// </remarks>
    protected override void OnAfterRender(bool firstRender)
    {
        if (firstRender)
        {
            Result = State.UdapMetadata.AsJson();
        }
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
