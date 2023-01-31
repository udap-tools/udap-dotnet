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
using IdentityModel.Client;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.WebUtilities;
using MudBlazor;
using Udap.Model;
using UdapClient.Client.Services;
using UdapClient.Shared;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Pages;

public partial class UdapBusinesstoBusiness
{
    [Inject] private HttpClient _httpClient { get; set; }
    private ErrorBoundary? ErrorBoundary { get; set; }

    [Inject] private UdapClientState State { get; set; }
    [Inject] private ProfileService ProfileService { get; set; }
    [Inject] AccessService AccessService { get; set; }
    [Inject] NavigationManager NavManager { get; set; }

    private string ClientId { get; set; } = "";
    private string? Oauth2Flow { get; set; }
    private string? TokenRequest1 { get; set; }
    private string? TokenRequest2 { get; set; }
    private string? TokenRequest3 { get; set; }
    private string? TokenRequest4 { get; set; }

    private string Password { get; set; } = "udap-test";
    private string? AuthorizeRequest { get; set; }
    public string? AccessToken { get; set; }
    public string? LoginCallback { get; set; }

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

    protected override async Task OnInitializedAsync()
    {
        // if (!State.IsLocalStorageInit)
        // {
        //     State = await ProfileService.GetUdapClientState();
        // }

        ClientId = State.RegistrationDocument?.ClientId ?? string.Empty;
        Oauth2Flow = State.Oauth2Flow.ToString();

        var uri = NavManager.ToAbsoluteUri(NavManager.Uri);
        LoginCallback = uri.Query.Replace("&", "&\r\n");

        var queryParams = QueryHelpers.ParseQuery(uri.Query);

        var loginCallbackResult = new LoginCallBackResult
        {
            Code = queryParams.GetValueOrDefault("code"),
            Scope = queryParams.GetValueOrDefault("scope"),
            State = queryParams.GetValueOrDefault("state"),
            SessionState = queryParams.GetValueOrDefault("session_state"),
            Issuer = queryParams.GetValueOrDefault("iss")
        };

        State.LoginCallBackResult = loginCallbackResult;
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
    private void BuildAuthCodeRequest()
    {
        var sb = new StringBuilder();
        sb.AppendLine("GET /authorize?");
        sb.AppendLine("\t response_type=code&");
        sb.AppendLine($"\t state={CryptoRandom.CreateUniqueId()}&");
        sb.AppendLine($"\t client_id={State.RegistrationDocument?.ClientId}&");
        sb.AppendLine($"\t scope= {State.RegistrationDocument?.Scope}&");
        sb.AppendLine($"\t redirect_uri={State.RegistrationDocument?.RedirectUris.FirstOrDefault()} HTTP/1.1");
        sb.AppendLine($"Host: {State.UdapMetadata?.AuthorizationEndpoint}");

        AuthorizeRequest = sb.ToString();
    }

    private async Task GetAccessCode()
    {
        var url = new RequestUrl(State.UdapMetadata?.AuthorizationEndpoint).CreateAuthorizeUrl(
            clientId: State.RegistrationDocument?.ClientId,
            responseType: "code",
            state: CryptoRandom.CreateUniqueId(),
            scope: State.RegistrationDocument?.Scope,
            redirectUri: State.RegistrationDocument?.RedirectUris.First()); //TODO: could let user pick


        State.AccessCodeRequestResult = await AccessService.Get(url);
    }

    private async Task BuildAccessTokenRequest ()
    {
        if (State.RegistrationDocument == null)
        {
            return;
        }

        if (string.IsNullOrEmpty(State.RegistrationDocument?.ClientId))
        {
            TokenRequest1 = "Missing ClientId";
            return;
        }

        if (string.IsNullOrEmpty(State.UdapMetadata?.TokenEndpoint))
        {
            TokenRequest1 = "Missing TokenEndpoint";
            return;
        }

        if (State.Oauth2Flow == Oauth2FlowEnum.authorization_code)
        {
            State.AuthorizationCodeTokenRequest = await AccessService
                .BuildRequestAccessTokenForAuthCode(
                    State.RegistrationDocument.ClientId,
                    State.UdapMetadata.TokenEndpoint,
                    Password);

            if (State.AuthorizationCodeTokenRequest == null)
            {
                TokenRequest1 = "Could not build an access token request";
                TokenRequest2 = string.Empty;
                TokenRequest3 = string.Empty;
                TokenRequest4 = string.Empty;

                return;
            }

            if (!string.IsNullOrEmpty(State.RegistrationDocument?.RedirectUris.First()))
            {
                State.AuthorizationCodeTokenRequest.RedirectUri =
                    State.RegistrationDocument?.RedirectUris.First();
            }
            
            if (State.AuthorizationCodeTokenRequest != null)
            {
                State.AuthorizationCodeTokenRequest.Code =
                    State.LoginCallBackResult.Code;
                var sb = new StringBuilder();
                sb.AppendLine("POST /token HTTP/1.1");
                sb.AppendLine($"Host: {State.UdapMetadata?.AuthorizationEndpoint}");
                sb.AppendLine("Content-type: application/x-www-form-urlencoded");
                sb.AppendLine();
                sb.AppendLine("grant_type=authorization_code&");
                TokenRequest1 = sb.ToString();

                sb = new StringBuilder();
                sb.AppendLine($"code={State.LoginCallBackResult.Code}&");
                sb.AppendLine($"client_assertion_type={OidcConstants.ClientAssertionTypes.JwtBearer}&");
                TokenRequest2 = sb.ToString();

                TokenRequest3 =
                    $"client_assertion={State.AuthorizationCodeTokenRequest?.ClientAssertion.Value}&\r\n";

                sb = new StringBuilder();
                if (!string.IsNullOrEmpty(State.AuthorizationCodeTokenRequest?.RedirectUri))
                {
                    sb.AppendLine($"redirect_uri={State.AuthorizationCodeTokenRequest.RedirectUri}");
                }
                sb.Append($"udap={UdapConstants.UdapVersionsSupportedValue}");
                TokenRequest4 = sb.ToString();
            }
        }
        else  //client_credentials
        {
            State.ClientCredentialsTokenRequest = await AccessService
                .BuildRequestAccessTokenForClientCredentials(
                    State.RegistrationDocument.ClientId,
                    State.UdapMetadata.TokenEndpoint,
                    Password);

            var sb = new StringBuilder();
            sb.AppendLine("POST /token HTTP/1.1");
            sb.AppendLine($"Host: {State.UdapMetadata?.AuthorizationEndpoint}");
            sb.AppendLine("Content-type: application/x-www-form-urlencoded");
            sb.AppendLine();
            sb.AppendLine("grant_type=client_credentials&");
            TokenRequest1 = sb.ToString();
            
            sb = new StringBuilder();
            sb.AppendLine($"client_assertion_type={OidcConstants.ClientAssertionTypes.JwtBearer}&");
            TokenRequest2 = sb.ToString();
            
            TokenRequest3 = $"client_assertion={State.ClientCredentialsTokenRequest?.ClientAssertion.Value}&";
            
            sb = new StringBuilder();
            sb.Append($"udap={UdapConstants.UdapVersionsSupportedValue}&\r\n");
            TokenRequest4 = sb.ToString();
        }
    }

    private async Task GetAccessToken()
    {
        if (State.Oauth2Flow == Oauth2FlowEnum.authorization_code)
        {
            if (State.AuthorizationCodeTokenRequest == null)
            {
                AccessToken = "Missing prerequisites.";
                return;
            }

            // still need to understand redirection
            var tokenResponse = await AccessService
                .RequestAccessTokenForAuthorizationCode(State.AuthorizationCodeTokenRequest);

            State.UpdateAccessTokens(this, tokenResponse);

            await ProfileService.SaveUdapClientState(State);

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
            if (State.ClientCredentialsTokenRequest == null)
            {
                AccessToken = "Missing prerequisites.";
                return;
            }

            var tokenResponse = await AccessService
                .RequestAccessTokenForClientCredentials(State.ClientCredentialsTokenRequest);

            // if (tokenResponse.IsError)
            // {
            //     AccessToken = tokenResponse.AsJson();
            // }
            // else
            // {
            //     AccessToken = tokenResponse.AccessToken;
            // }
            AccessToken = tokenResponse;
        }
    }
}
