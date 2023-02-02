#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text;
using IdentityModel;

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.WebUtilities;
using MudBlazor;
using Udap.Model;
using UdapClient.Client.Services;
using UdapClient.Client.Shared;
using UdapClient.Shared;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Pages;

public partial class UdapBusinesstoBusiness
{
    [CascadingParameter]
    public CascadingAppState AppState { get; set; } = null!;

    [Inject] private HttpClient _httpClient { get; set; }
    private ErrorBoundary? ErrorBoundary { get; set; }

    [Inject] AccessService AccessService { get; set; }
    [Inject] NavigationManager NavManager { get; set; }

    private string _clientId = "";

    private string ClientId
    {
        get
        {
            _clientId = AppState.RegistrationDocument?.ClientId;
            return _clientId;
        } set
        {
            _clientId = value; // not used.  Makes binding happy because it needs a settable property
        }
    }

    private string _oauth2Flow;

    private string? Oauth2Flow
    {
        get
        {
            _oauth2Flow = AppState.Oauth2Flow.ToString();
            return _oauth2Flow;
        }
        set
        {
            _oauth2Flow = value;
        }
    }

    private string? TokenRequest1 { get; set; }
    private string? TokenRequest2 { get; set; }
    private string? TokenRequest3 { get; set; }
    private string? TokenRequest4 { get; set; }

    private string Password { get; set; } = "udap-test";

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
        get
        {
            if (_accessToken == null)
            {
                _accessToken = AppState.AccessTokens?.Raw;
            }
            return _accessToken;
        }
        set
        {
            _accessToken = value;
        }
    }

    public string? LoginCallback() {
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

    bool _isShow;
    InputType _passwordInput = InputType.Password;
    string _passwordInputIcon = Icons.Material.Filled.VisibilityOff;

    void ShowPassword()
    {
        if (_isShow)
        {
            _isShow = false;
            _passwordInputIcon = Icons.Material.Filled.VisibilityOff;
            _passwordInput = InputType.Password;
        }
        else
        {
            _isShow = true;
            _passwordInputIcon = Icons.Material.Filled.Visibility;
            _passwordInput = InputType.Text;
        }
    }

    
    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
        BuildAccessTokenRequestVisual();
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
    private void BuildAuthCodeRequest()
    {
        AuthorizationCodeRequest = new AuthorizationCodeRequest
        {
            ResponseType = "response_type=code",
            State = $"state={CryptoRandom.CreateUniqueId()}",
            ClientId = $"client_id={AppState.RegistrationDocument?.ClientId}",
            Scope = $"scope={AppState.RegistrationDocument?.Scope}",
            RedirectUri = $"redirect_uri={AppState.RegistrationDocument?.RedirectUris.FirstOrDefault()}"
        };

        AppState.SetProperty(this, nameof(AppState.AuthorizationCodeRequest), AuthorizationCodeRequest, true, false);
    }

    private async Task GetAccessCode()
    {
        //UI has been changing properties so save it but don't rebind
        AppState.SetProperty(this, nameof(AppState.AuthorizationCodeRequest), AuthorizationCodeRequest, true, false);
        var url = new RequestUrl(AppState.UdapMetadata?.AuthorizationEndpoint!);

        var accessCodeRequestUrl = url.AppendParams(
            AppState.AuthorizationCodeRequest?.ClientId,
            AppState.AuthorizationCodeRequest?.ResponseType,
            AppState.AuthorizationCodeRequest?.State,
            AppState.AuthorizationCodeRequest?.Scope,
            AppState.AuthorizationCodeRequest?.RedirectUri);

        Console.WriteLine(accessCodeRequestUrl);
        //
        // Builds an anchor href link the user clicks to initiate a user login page at the authorization server
        //
        AppState.SetProperty(this, nameof(AppState.AccessCodeRequestResult), await AccessService.Get(accessCodeRequestUrl));
    }

    private async Task BuildAccessTokenRequest ()
    {
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
            var requestToken = await AccessService
                .BuildRequestAccessTokenForAuthCode(
                    AppState.RegistrationDocument.ClientId,
                    AppState.UdapMetadata.TokenEndpoint,
                    Password);
            
            AppState.SetProperty(this, nameof(AppState.AuthorizationCodeTokenRequest), requestToken);

            if (AppState.AuthorizationCodeTokenRequest == null)
            {
                TokenRequest1 = "Could not build an access token request";
                TokenRequest2 = string.Empty;
                TokenRequest3 = string.Empty;
                TokenRequest4 = string.Empty;

                return;
            }

            if (!string.IsNullOrEmpty(AppState.RegistrationDocument?.RedirectUris.First()))
            {
                AppState.AuthorizationCodeTokenRequest.RedirectUri =
                    AppState.RegistrationDocument?.RedirectUris.First();
            }
            
            if (AppState.AuthorizationCodeTokenRequest != null)
            {
                AppState.AuthorizationCodeTokenRequest.Code = AppState.LoginCallBackResult?.Code;
                BuildAccessTokenRequestVisual();
            }
        }
        else  //client_credentials
        {
            var requestToken = await AccessService
                .BuildRequestAccessTokenForClientCredentials(
                    AppState.RegistrationDocument.ClientId,
                    AppState.UdapMetadata.TokenEndpoint,
                    Password);

            AppState.SetProperty(this, nameof(AppState.ClientCredentialsTokenRequest), requestToken);

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
            
            TokenRequest3 = $"client_assertion={AppState.ClientCredentialsTokenRequest?.ClientAssertion.Value}&";
            
            sb = new StringBuilder();
            sb.Append($"udap={UdapConstants.UdapVersionsSupportedValue}&\r\n");
            TokenRequest4 = sb.ToString();
        }
    }

    private void BuildAccessTokenRequestVisual()
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
        sb.AppendLine($"code={AppState.LoginCallBackResult?.Code}&");
        sb.AppendLine($"client_assertion_type={OidcConstants.ClientAssertionTypes.JwtBearer}&");
        TokenRequest2 = sb.ToString();

        TokenRequest3 =
            $"client_assertion={AppState.AuthorizationCodeTokenRequest?.ClientAssertion.Value}&\r\n";

        sb = new StringBuilder();
        if (!string.IsNullOrEmpty(AppState.AuthorizationCodeTokenRequest?.RedirectUri))
        {
            sb.AppendLine($"redirect_uri={AppState.AuthorizationCodeTokenRequest.RedirectUri}");
        }

        sb.Append($"udap={UdapConstants.UdapVersionsSupportedValue}");
        TokenRequest4 = sb.ToString();
    }

    private async Task GetAccessToken()
    {
        if (AppState.Oauth2Flow == Oauth2FlowEnum.authorization_code)
        {
            if (AppState.AuthorizationCodeTokenRequest == null)
            {
                AccessToken = "Missing prerequisites.";
                return;
            }
                       
            var tokenResponse = await AccessService
                .RequestAccessTokenForAuthorizationCode(AppState.AuthorizationCodeTokenRequest);
            
            AppState.SetProperty(this, nameof(AppState.AccessTokens), tokenResponse);
            
            if (tokenResponse != null && !tokenResponse.IsError)
            {
                AccessToken = tokenResponse.Raw;
            }
            else
            {
                AccessToken = tokenResponse?.Error;
            }
        }
        else //client_credentials
        {
            if (AppState.ClientCredentialsTokenRequest == null)
            {
                AccessToken = "Missing prerequisites.";
                return;
            }

            var tokenResponse = await AccessService
                .RequestAccessTokenForClientCredentials(AppState.ClientCredentialsTokenRequest);
            
            AccessToken = tokenResponse;
        }
    }
}
