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
using BQuery;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.IdentityModel.Tokens;
using MudBlazor;
using UdapEd.Client.Services;
using UdapEd.Client.Shared;
using UdapEd.Shared;
using UdapEd.Shared.Model;

namespace UdapEd.Client.Pages;

public partial class UdapDiscovery: IDisposable
{
    [CascadingParameter]
    public CascadingAppState AppState { get; set; } = null!;
    
    ErrorBoundary? ErrorBoundary { get; set; }
    
    [Inject] DiscoveryService MetadataService { get; set; } = null!;

    [Inject] NavigationManager NavigationManager { get; set; } = null!;

    [Inject] private DiscoveryService DiscoveryService { get; set; } = null!;

    readonly PeriodicTimer _periodicTimer = new PeriodicTimer(TimeSpan.FromMinutes(5));
    
    private bool _checkServerSession;

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
                return _result ?? string.Empty;
            }

            return JsonSerializer.Serialize(AppState.UdapMetadata, new JsonSerializerOptions { WriteIndented = true });
        }
        set => _result = value;
    }

    private string? _baseUrl;

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

    private string? _community;

    private string? Community
    {
        get
        {
            if (!string.IsNullOrEmpty(_community))
            {
                return _community;
            }

            _community = AppState.Community;

            return _community;
        }
        set
        {
            _community = value;
            AppState.SetProperty(this, nameof(AppState.Community), _community);
        }
    }

    public Color CertLoadedColor { get; set; } = Color.Error;

    protected override async Task OnInitializedAsync()
    {
        var clientCertificateLoadStatus = await DiscoveryService.AnchorCertificateLoadStatus();
        await AppState.SetPropertyAsync(this, nameof(AppState.ClientCertificateInfo), clientCertificateLoadStatus);
        await SetCertLoadedColor(clientCertificateLoadStatus?.CertLoaded);
        RunTimer();
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            Bq.Events.OnBlur += Events_OnBlur;
            Bq.Events.OnFocusAsync += Events_OnFocus;
        }
        await base.OnAfterRenderAsync(firstRender);
    }

    private async Task Events_OnFocus(FocusEventArgs obj)
    {
        var clientCertificateLoadStatus = await DiscoveryService.AnchorCertificateLoadStatus();
        await AppState.SetPropertyAsync(this, nameof(AppState.ClientCertificateInfo), clientCertificateLoadStatus);
        await SetCertLoadedColor(clientCertificateLoadStatus?.CertLoaded);
        _checkServerSession = true;
    }

    private void Events_OnBlur(FocusEventArgs obj)
    {
        _checkServerSession = false;
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
                await MetadataService.GetMetadata(RequestUrl.GetWellKnownUdap(BaseUrl, Community), default));

            Result = AppState.UdapMetadata != null
                ? JsonSerializer.Serialize(AppState.UdapMetadata, new JsonSerializerOptions { WriteIndented = true })
                : string.Empty;
            await AppState.SetPropertyAsync(this, nameof(AppState.BaseUrl), BaseUrl);

            if (_result != null && _result.Contains("udap_versions_supported"))
            {
                AppendOrMoveBaseUrl(BaseUrl);
            }
            else
            {
                await RemoveBaseUrl();
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
        await Task.Delay(5, token);

        if (AppState.BaseUrls == null)
        {
            await AppState.SetPropertyAsync(this, nameof(AppState.BaseUrls), new OrderedDictionary(), true, false);
        }

        if (AppState.BaseUrls!.Contains(value))
        {
            return AppState.BaseUrls.Cast<DictionaryEntry>().Select(e => (string)e.Key);
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out var baseUri))
        {
            var result = await MetadataService.GetMetadata(RequestUrl.GetWellKnownUdap(BaseUrl, Community), token);
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

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }

    private string GetJwtHeader()
    {
        var jwt = new JwtSecurityToken(AppState.UdapMetadata?.SignedMetadata);
        return UdapEd.Shared.JsonExtensions.FormatJson(Base64UrlEncoder.Decode(jwt.EncodedHeader));
    }

    private async Task UploadFilesAsync(InputFileChangeEventArgs e)
    {
        long maxFileSize = 1024 * 10;

        var uploadStream = await new StreamContent(e.File.OpenReadStream(maxFileSize)).ReadAsStreamAsync();
        var ms = new MemoryStream();
        await uploadStream.CopyToAsync(ms);
        var certBytes = ms.ToArray();

        var certViewModel = await DiscoveryService.UploadAnchorCertificate(Convert.ToBase64String(certBytes));

        await SetCertLoadedColor(certViewModel?.CertLoaded);
        await AppState.SetPropertyAsync(this, nameof(AppState.AnchorCertificateInfo), certViewModel);
    }

    private async Task SetCertLoadedColor(CertLoadedEnum? isCertLoaded)
    {
        switch (isCertLoaded)
        {
            case CertLoadedEnum.Negative:
                CertLoadedColor = Color.Error;
                await AppState.SetPropertyAsync(this, nameof(AppState.AnchorLoaded), false);
                break;
            case CertLoadedEnum.Positive:
                CertLoadedColor = Color.Success;
                await AppState.SetPropertyAsync(this, nameof(AppState.AnchorLoaded), true);
                break;
            case CertLoadedEnum.InvalidPassword:
                CertLoadedColor = Color.Warning;
                await AppState.SetPropertyAsync(this, nameof(AppState.AnchorLoaded), false);
                break;
            default:
                CertLoadedColor = Color.Error;
                await AppState.SetPropertyAsync(this, nameof(AppState.AnchorLoaded), false);
                break;
        }

        this.StateHasChanged();
    }

    async void RunTimer()
    {
        while (await _periodicTimer.WaitForNextTickAsync())
        {
            if (_checkServerSession)
            {
                var certViewModel = await DiscoveryService.AnchorCertificateLoadStatus();
                await AppState.SetPropertyAsync(this, nameof(AppState.ClientCertificateInfo), certViewModel);
                await SetCertLoadedColor(certViewModel?.CertLoaded);
            }
        }
    }

    public void Dispose()
    {
        _periodicTimer.Dispose();
    }
}
