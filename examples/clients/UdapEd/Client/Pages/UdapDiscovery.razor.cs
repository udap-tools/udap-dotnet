#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.IdentityModel.Tokens;
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

    [Inject] NavigationManager NavigationManager { get; set; } = null!;

    private string? _result;

    private string Result
    {
        get
        {
            if (_result != null)
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

    private string _baseUrl;

    private string? BaseUrl
    {
        get
        {
            if (!string.IsNullOrEmpty(_baseUrl))
            {
                return _baseUrl;
            }

            _baseUrl = AppState.BaseUrl;

            return _baseUrl;
        }
        set
        {
            _baseUrl = value;
        }
    }

    private async Task GetMetadata()
    {
        Result = "Loading ...";
        await Task.Delay(1000);

        try
        {
            await AppState.SetPropertyAsync(
                this, 
                nameof(AppState.UdapMetadata), 
                await MetadataService.GetMetadata(GetWellKnownUdap(BaseUrl), default));

            Result = AppState.UdapMetadata != null
                ? JsonSerializer.Serialize(AppState.UdapMetadata, new JsonSerializerOptions { WriteIndented = true })
                : string.Empty;
            await AppState.SetPropertyAsync(this, nameof(AppState.BaseUrl), BaseUrl);

            if (_result.Contains("udap_versions_supported"))
            {
                AppendOrMoveBaseUrl(BaseUrl);
            }
            else
            {
                RemoveBaseUrl();
            }
        }
        catch (Exception ex)
        {
            Result = ex.Message;
            await AppState.SetPropertyAsync(this, nameof(AppState.UdapMetadata), null);
        }
    }

    private async Task<IEnumerable<string>?> GetMetadata(string value, CancellationToken token)
    {
        await Task.Delay(5);

        if (AppState.BaseUrls == null)
        {
            AppState.SetProperty(this, nameof(AppState.BaseUrls), new OrderedDictionary(), true, false);
        }

        if (AppState.BaseUrls!.Contains(value))
        {
            return AppState.BaseUrls.Cast<DictionaryEntry>().Select(e => (string)e.Key);
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out var baseUri))
        {
            var result = await MetadataService.GetMetadata(GetWellKnownUdap(BaseUrl), token);
            if (result != null)
            {
                AppendOrMoveBaseUrl(baseUri.AbsoluteUri);
            }
        }

        return AppState.BaseUrls.Cast<DictionaryEntry>().Select(e => (string)e.Key);
    }

    private void AppendOrMoveBaseUrl(string? appStateBaseUrl)
    {
        var baseUrls = AppState.BaseUrls;
        if (baseUrls != null && appStateBaseUrl != null)
        {
            if (!baseUrls.Contains(appStateBaseUrl) && !baseUrls.Contains(appStateBaseUrl.TrimEnd('/')))
            {
                baseUrls.Insert(0, appStateBaseUrl, null);
            }
            else
            {   //Move
                baseUrls.Remove(appStateBaseUrl);
                baseUrls.Insert(0, appStateBaseUrl, null);
            }
            AppState.SetProperty(this, nameof(AppState.BaseUrls), baseUrls);
        }
    }
    
    private async Task RemoveBaseUrl()
    {
        Result = "Saving ...";
        await Task.Delay(50);
        var baseUrls = AppState.BaseUrls;
        if (BaseUrl != null)
        {
            baseUrls?.Remove(BaseUrl);
        }
        
        BaseUrl = string.Empty;
        await AppState.SetPropertyAsync(this, nameof(AppState.BaseUrls), baseUrls);
        await AppState.SetPropertyAsync(this, nameof(AppState.BaseUrl), string.Empty);

        Result = "";
        NavigationManager.NavigateTo("udapDiscovery", true);
    }

    private string? GetWellKnownUdap(string? baseUrl)
    {
        if (!string.IsNullOrEmpty(baseUrl) && !baseUrl.EndsWith(UdapConstants.Discovery.DiscoveryEndpoint, StringComparison.OrdinalIgnoreCase))
        {
            return $"{baseUrl!.RemoveTrailingSlash()}{UdapConstants.Discovery.DiscoveryEndpoint}" ;
        }

        return baseUrl ;
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }

    private string? GetJwtHeader()
    {
        var jwt = new JwtSecurityToken(AppState.UdapMetadata?.SignedMetadata);
        return UdapEd.Shared.JsonExtensions.FormatJson(Base64UrlEncoder.Decode(jwt.EncodedHeader));
    }
}
