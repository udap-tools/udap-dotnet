#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using IdentityModel;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Microsoft.JSInterop;
using Udap.Model;
using UdapEd.Client.Services;
using UdapEd.Client.Shared;
using UdapEd.Shared;
using UdapEd.Shared.Model;
using JsonExtensions = UdapEd.Shared.JsonExtensions;

namespace UdapEd.Client.Pages;

public partial class UdapBusinessToBusiness
{
    [CascadingParameter]
    public CascadingAppState AppState { get; set; } = null!;

    private ErrorBoundary? ErrorBoundary { get; set; }

    [Inject] AccessService AccessService { get; set; } = null!;
    [Inject] NavigationManager NavManager { get; set; } = null!;
    
    [Inject] private IJSRuntime JSRuntime { get; set; } = null!;

    private string LoginRedirectLinkText { get; set; } = "Login Redirect";

    public bool LegacyMode { get; set; } = false;

    private string? _clientId = "";

    private string? ClientId
    {
        get
        {
            if (string.IsNullOrEmpty(_clientId) )
            {
                _clientId = AppState.RegistrationDocument?.ClientId;
            }
            
            return _clientId;
        }
        set
        {
            _clientId = value;
            if (AppState.RegistrationDocument != null)
            {
                AppState.RegistrationDocument.ClientId = value;
            }
        }
        
    }

    private string? _oauth2Flow;

    private string? Oauth2Flow
    {
        get
        {
            _oauth2Flow = AppState.Oauth2Flow.ToString();
            return _oauth2Flow;
        }
        set => _oauth2Flow = value;
    }

    private string? TokenRequest1 { get; set; }
    private string? TokenRequest2 { get; set; }
    private string? TokenRequest3 { get; set; }
    private string? TokenRequestScope { get; set; }
    private string? TokenRequest4 { get; set; }

    public string? ClientAssertionDecoded { get; set; }


    private AuthorizationCodeRequest? _authorizationCodeRequest;
    private AuthorizationCodeRequest? AuthorizationCodeRequest {
        get
        {
            if (_authorizationCodeRequest == null)
            {
                _authorizationCodeRequest = AppState.AuthorizationCodeRequest;
            }
            return _authorizationCodeRequest;
        }
        set
        {
            _authorizationCodeRequest = value;
            AppState.SetProperty(this, nameof(AppState.AuthorizationCodeRequest), value);
        }
    }

    private string? _accessToken;

    private string? AccessToken
    {
        get { return _accessToken ??= AppState.AccessTokens?.Raw; }
        set => _accessToken = value;
    }

   

    /// <summary>
    /// Method invoked when the component is ready to start, having received its
    /// initial parameters from its parent in the render tree.
    /// Override this method if you will perform an asynchronous operation and
    /// want the component to refresh when that operation is completed.
    /// </summary>
    /// <returns>A <see cref="T:System.Threading.Tasks.Task" /> representing any asynchronous operation.</returns>
    protected override Task OnInitializedAsync()
    {
        ResetSoftwareStatement();
        
        return base.OnInitializedAsync();
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }

    /// <summary>
    /// GET /authorize?
    ///     response_type=code&
    ///     state=client_random_state&
    ///     client_id=clientIDforResourceHolder&
    ///     scope= resource_scope1+resource_scope2&
    ///     redirect_uri=https://client.example.net/clientredirect HTTP/1.1
    /// Host: resourceholder.example.com
    /// </summary>
    /// <exception cref="NotImplementedException"></exception>
    private async Task BuildAuthCodeRequest()
    {
        AccessToken = string.Empty;
        AppState.SetProperty(this, nameof(AppState.AccessTokens), string.Empty, true, false);
        AuthorizationCodeRequest = new AuthorizationCodeRequest
        {
            RedirectUri = "Loading..."
        };

        AppState.SetProperty(this, nameof(AppState.AuthorizationCodeRequest), AuthorizationCodeRequest, true, false);
        await Task.Delay(250);

        AuthorizationCodeRequest = new AuthorizationCodeRequest
        {
            ResponseType = "response_type=code",
            State = $"state={CryptoRandom.CreateUniqueId()}",
            ClientId = $"client_id={AppState.RegistrationDocument?.ClientId}",
            Scope = $"scope={AppState.SoftwareStatementBeforeEncoding?.Scope}",
            RedirectUri = $"redirect_uri={AppState.RegistrationDocument?.RedirectUris.FirstOrDefault()}",
            Aud = $"aud={AppState.BaseUrl}"
        };

        AppState.SetProperty(this, nameof(AppState.AuthorizationCodeRequest), AuthorizationCodeRequest, true, false);

        BuildAuthorizeLink();
    }

    private string AuthCodeRequestLink { get; set; } = string.Empty;
    
    private void BuildAuthorizeLink()
    {
        var sb = new StringBuilder();
        sb.Append(@AppState.UdapMetadata?.AuthorizationEndpoint);
        if (@AppState.AuthorizationCodeRequest != null)
        {
            sb.Append("?").Append(@AppState.AuthorizationCodeRequest.ResponseType);
            sb.Append("&").Append(@AppState.AuthorizationCodeRequest.State);
            sb.Append("&").Append(@AppState.AuthorizationCodeRequest.ClientId);
            sb.Append("&").Append(@AppState.AuthorizationCodeRequest.Scope);
            sb.Append("&").Append(@AppState.AuthorizationCodeRequest.RedirectUri);
            sb.Append("&").Append(@AppState.AuthorizationCodeRequest.Aud);
        }

        AuthCodeRequestLink = sb.ToString();
        StateHasChanged();
    }

    private async Task GetAccessCode()
    {
        LoginRedirectLinkText = "Loading...";
        AppState.SetProperty(this, nameof(AppState.AccessCodeRequestResult), null);

        //UI has been changing properties so save it but don't rebind
        AppState.SetProperty(this, nameof(AppState.AuthorizationCodeRequest), AuthorizationCodeRequest, true, false);
        var url = new RequestUrl(AppState.UdapMetadata?.AuthorizationEndpoint!);

        var accessCodeRequestUrl = url.AppendParams(
            AppState.AuthorizationCodeRequest?.ClientId,
            AppState.AuthorizationCodeRequest?.ResponseType,
            AppState.AuthorizationCodeRequest?.State,
            AppState.AuthorizationCodeRequest?.Scope,
            AppState.AuthorizationCodeRequest?.RedirectUri,
            AppState.AuthorizationCodeRequest?.Aud);

        Console.WriteLine(accessCodeRequestUrl);
        //
        // Builds an anchor href link the user clicks to initiate a user login page at the authorization server
        //
        var loginLink = await AccessService.Get(accessCodeRequestUrl);
        
        AppState.SetProperty(this, nameof(AppState.AccessCodeRequestResult), loginLink);
        LoginRedirectLinkText = "Login Redirect";
    }

    public string LoginCallback(bool reset = false)
    {
        if (reset)
        {
            return string.Empty;
        }

        var uri = NavManager.ToAbsoluteUri(NavManager.Uri);

        if (!string.IsNullOrEmpty(uri.Query))
        {
            var queryParams = QueryHelpers.ParseQuery(uri.Query);

            var loginCallbackResult = new LoginCallBackResult
            {
                Code = queryParams.GetValueOrDefault("code"),
                Scope = queryParams.GetValueOrDefault("scope"),
                State = queryParams.GetValueOrDefault("state"),
                SessionState = queryParams.GetValueOrDefault("session_state"),
                Issuer = queryParams.GetValueOrDefault("iss")
            };

            AppState.SetProperty(this, nameof(AppState.LoginCallBackResult), loginCallbackResult, true, false);
        }

        return uri.Query.Replace("&", "&\r\n");
    }
    
    private void ResetSoftwareStatement()
    {
        TokenRequest1 = string.Empty;
        TokenRequest2 = string.Empty;
        AppState.SetProperty(this, nameof(AppState.UdapRegistrationRequest), null);
        TokenRequest3 = string.Empty;
        TokenRequest4 = string.Empty;
        AppState.SetProperty(this, nameof(AppState.AuthorizationCodeRequest), null);
        LoginCallback(true);
        StateHasChanged();
    }

    private async Task BuildAccessTokenRequest ()
    {
        ResetSoftwareStatement();
        TokenRequest1 = "Loading ...";
        await Task.Delay(50);

        if (AppState.RegistrationDocument == null)
        {
            return;
        }

        if (string.IsNullOrEmpty(AppState.RegistrationDocument?.ClientId))
        {
            TokenRequest1 = "Missing ClientId";
            return;
        }

        if (string.IsNullOrEmpty(AppState.UdapMetadata?.TokenEndpoint))
        {
            TokenRequest1 = "Missing TokenEndpoint";
            return;
        }

        if (AppState.Oauth2Flow == Oauth2FlowEnum.authorization_code)
        {
            var tokenRequestModel = new AuthorizationCodeTokenRequestModel
            {
                ClientId = AppState.RegistrationDocument.ClientId,
                TokenEndpointUrl = AppState.UdapMetadata.TokenEndpoint,
            };

            if (AppState.RegistrationDocument?.RedirectUris.Count > 0)
            {
                tokenRequestModel.RedirectUrl = AppState.RegistrationDocument?.RedirectUris.First() ?? string.Empty;
            }

            if (AppState.LoginCallBackResult?.Code != null)
            {
                tokenRequestModel.Code = AppState.LoginCallBackResult?.Code!;
            }

            tokenRequestModel.LegacyMode = LegacyMode;

            var requestToken = await AccessService
                .BuildRequestAccessTokenForAuthCode(tokenRequestModel);
            
            AppState.SetProperty(this, nameof(AppState.AuthorizationCodeTokenRequest), requestToken);

            if (AppState.AuthorizationCodeTokenRequest == null)
            {
                TokenRequest1 = "Could not build an access token request";
                TokenRequest2 = string.Empty;
                TokenRequest3 = string.Empty;
                TokenRequest4 = string.Empty;

                return;
            }

            BuildAccessTokenRequestVisualForAuthorizationCode();
        }
        else  //client_credentials
        {
            var tokenRequestModel = new ClientCredentialsTokenRequestModel
            {
                ClientId = AppState.RegistrationDocument.ClientId,
                TokenEndpointUrl = AppState.UdapMetadata.TokenEndpoint,
                LegacyMode = LegacyMode,
                Scope = AppState.SoftwareStatementBeforeEncoding?.Scope
            };

            var requestToken = await AccessService
                .BuildRequestAccessTokenForClientCredentials(tokenRequestModel);

            AppState.SetProperty(this, nameof(AppState.ClientCredentialsTokenRequest), requestToken);

            BuildAccessTokenRequestVisualForClientCredentials();
        }
    }

    private void BuildAccessTokenRequestVisualForClientCredentials()
    {
        var sb = new StringBuilder();
        sb.AppendLine("POST /token HTTP/1.1");
        sb.AppendLine($"Host: {AppState.UdapMetadata?.AuthorizationEndpoint}");
        sb.AppendLine("Content-type: application/x-www-form-urlencoded");
        sb.AppendLine();
        sb.AppendLine("grant_type=client_credentials&");
        TokenRequest1 = sb.ToString();

        sb = new StringBuilder();
        sb.AppendLine($"client_assertion_type={OidcConstants.ClientAssertionTypes.JwtBearer}&");
        TokenRequest2 = sb.ToString();

        TokenRequest3 = $"client_assertion={AppState.ClientCredentialsTokenRequest?.ClientAssertion?.Value}&";
        TokenRequestScope = $"scope={AppState.ClientCredentialsTokenRequest?.Scope}&";
        sb = new StringBuilder();
        sb.Append($"udap={UdapConstants.UdapVersionsSupportedValue}&\r\n");
        TokenRequest4 = sb.ToString();

        sb = new StringBuilder();
        sb.AppendLine("<p class=\"text-line\">HEADER: <span>Algorithm & TOKEN TYPE</span></p>");
        var jwt = new JwtSecurityToken(AppState.ClientCredentialsTokenRequest?.ClientAssertion?.Value);
        sb.AppendLine($"{JsonExtensions.FormatJson(Base64UrlEncoder.Decode(jwt.EncodedHeader))}");
        sb.AppendLine("<p class=\"text-line\">PAYLOAD: <span>DATA</span></p>");
        // .NET 7 Blazor Json does not deserialize complex JWT payloads like the extensions object.
        sb.AppendLine(JsonSerializer.Serialize(jwt.Payload, new JsonSerializerOptions { WriteIndented = true }));
        ClientAssertionDecoded = sb.ToString();
    }

    private void BuildAccessTokenRequestVisualForAuthorizationCode()
    {
        if (AppState.LoginCallBackResult == null)
        {
            return;
        }

        var sb = new StringBuilder();
        sb.AppendLine("POST /token HTTP/1.1");
        sb.AppendLine($"Host: {AppState.UdapMetadata?.AuthorizationEndpoint}");
        sb.AppendLine("Content-type: application/x-www-form-urlencoded");
        sb.AppendLine();
        sb.AppendLine("grant_type=authorization_code&");
        TokenRequest1 = sb.ToString();

        sb = new StringBuilder();
        sb.AppendLine($"code={AppState.AuthorizationCodeTokenRequest?.Code}&");
        sb.AppendLine($"client_assertion_type={OidcConstants.ClientAssertionTypes.JwtBearer}&");
        TokenRequest2 = sb.ToString();

        TokenRequest3 =
            $"client_assertion={AppState.AuthorizationCodeTokenRequest?.ClientAssertion?.Value}&\r\n";

        sb = new StringBuilder();
        if (!string.IsNullOrEmpty(AppState.AuthorizationCodeTokenRequest?.RedirectUri))
        {
            sb.AppendLine($"redirect_uri={AppState.AuthorizationCodeTokenRequest.RedirectUri}");
        }

        sb.Append($"udap={UdapConstants.UdapVersionsSupportedValue}");
        TokenRequest4 = sb.ToString();


        sb = new StringBuilder();
        sb.AppendLine("<p class=\"text-line\">HEADER: <span>Algorithm & TOKEN TYPE</span></p>");
        var jwt = new JwtSecurityToken(AppState.AuthorizationCodeTokenRequest?.ClientAssertion?.Value);
        sb.AppendLine($"{JsonExtensions.FormatJson(Base64UrlEncoder.Decode(jwt.EncodedHeader))}");
        sb.AppendLine("<p class=\"text-line\">PAYLOAD: <span>DATA</span></p>");
        sb.AppendLine(JsonSerializer.Serialize(jwt.Payload, new JsonSerializerOptions { WriteIndented = true }));
        ClientAssertionDecoded = sb.ToString();
    }

    private async Task GetAccessToken()
    {
        try
        {
            AccessToken = "Loading ...";
            await Task.Delay(150);

            if (AppState.Oauth2Flow == Oauth2FlowEnum.authorization_code)
            {
                if (AppState.AuthorizationCodeTokenRequest == null)
                {
                    AccessToken = "Missing prerequisites.";
                    return;
                }

                var tokenResponse = await AccessService
                    .RequestAccessTokenForAuthorizationCode(
                        AppState.AuthorizationCodeTokenRequest);

                AppState.SetProperty(this, nameof(AppState.AccessTokens), tokenResponse);

                AccessToken = tokenResponse is { IsError: false } ? tokenResponse.Raw : tokenResponse?.Error;
            }
            else //client_credentials
            {
                if (AppState.ClientCredentialsTokenRequest == null)
                {
                    AccessToken = "Missing prerequisites.";
                    return;
                }

                var tokenResponse = await AccessService
                    .RequestAccessTokenForClientCredentials(
                        AppState.ClientCredentialsTokenRequest);

                AppState.SetProperty(this, nameof(AppState.AccessTokens), tokenResponse);

                AccessToken = tokenResponse is { IsError: false }
                    ? tokenResponse.Raw 
                    : $"Failed:\r\n\r\n{tokenResponse?.Error}\r\n{tokenResponse?.Headers}";
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            Console.WriteLine(ex);
        }
    }

    private async Task LaunchAuthorize()
    {
        BuildAuthorizeLink();

        await JSRuntime.InvokeVoidAsync("open", @AuthCodeRequestLink, "_self");
    }
}
