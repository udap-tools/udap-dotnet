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
using Udap.Client.Internal;
using Udap.Model;
using UdapEd.Client.Services;
using UdapEd.Client.Shared;

namespace UdapEd.Client.Pages;

public partial class UdapDiscovery
{
    [CascadingParameter]
    public CascadingAppState AppState { get; set; } = null!;
    
    ErrorBoundary? ErrorBoundary { get; set; }
    
    [Inject] DiscoveryService MetadataService { get; set; } = null!;

    private string _result = string.Empty;

    private string Result
    {
        get
        {
            if (!string.IsNullOrEmpty(_result))
            {
                return _result;
            }   

            if (AppState.UdapMetadata == null)
            {
                return _result;
            }

            return JsonSerializer.Serialize(AppState.UdapMetadata, new JsonSerializerOptions { WriteIndented = true });
        }
        set => _result = value;
    }

    private string? BaseUrl
    {
        get => AppState.BaseUrl;
        set
        {
            //Todo: retain multiple URls to pick from
        }
    }

    public void SetMetadataUrlProperty(string value)
    {
        BaseUrl = value;
        AppState.SetProperty(this, nameof(AppState.BaseUrl), value);
    }

    private async Task GetMetadata()
    {
        Result = "Loading ...";
        await Task.Delay(50);

        try
        {
            AppState.SetProperty(this, nameof(AppState.UdapMetadata), await MetadataService.GetMetadata(GetWellKnownUdap(AppState.BaseUrl)));
            
            _result = AppState.UdapMetadata != null
                ? JsonSerializer.Serialize(AppState.UdapMetadata, new JsonSerializerOptions { WriteIndented = true })
                : string.Empty;
        }
        catch (Exception ex)
        {
            _result = ex.Message;
            AppState.SetProperty(this, nameof(AppState.UdapMetadata), null);
        }
    }

    private string? GetWellKnownUdap(string? baseUrl)
    {
        return $"{baseUrl.RemoveTrailingSlash()}{UdapConstants.Discovery.DiscoveryEndpoint}";
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
