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

    [Inject] private UdapClientState UdapClientState { get; set; } = new UdapClientState();
    [Inject] private ProfileService ProfileService { get; set; }
    [Inject] AccessService AccessService { get; set; }
    [Inject] NavigationManager NavManager { get; set; }

    private string ClientId { get; set; } = "";
    private string? Oauth2Flow { get; set; }
    private string? TokenRequest1 { get; set; }
    private string? TokenRequest2 { get; set; }
    private string? TokenRequest3 { get; set; }
    private string? TokenRequest4 { get; set; }

    private TokenResponse? TokenResponse { get; set; }
    private string Password { get; set; } = "udap-test";
    private string AuthorizeRequest { get; set; }
    public string AccessToken { get; set; }
    public string LoginCallback { get; set; }

    bool isShow;
    InputType PasswordInput = InputType.Password;
    string PasswordInputIcon = Icons.Material.Filled.VisibilityOff;

    void ShowPassword()
    {
        if (isShow)
        {
            isShow = false;
            PasswordInputIcon = Icons.Material.Filled.VisibilityOff;
            PasswordInput = InputType.Password;
        }
        else
        {
            isShow = true;
            PasswordInputIcon = Icons.Material.Filled.Visibility;
            PasswordInput = InputType.Text;
        }
    }

    protected override async Task OnInitializedAsync()
    {
        if (!UdapClientState.IsLocalStorageInit())
        {
            UdapClientState = await ProfileService.GetUdapClientState();
        }

        ClientId = UdapClientState.RegistrationDocument?.ClientId ?? string.Empty;
        Oauth2Flow = UdapClientState.Oauth2Flow.ToString();

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

        UdapClientState.LoginCallBackResult = loginCallbackResult;
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }

    private async Task GetAccessToken()
    {
        if (UdapClientState.Oauth2Flow == Oauth2FlowEnum.authorization_code)
        {
            // still need to understand redirection
            var tokenResponse = await AccessService
                .RequestAccessTokenForAuthorizationCode(UdapClientState.AuthorizationCodeTokenRequest);

            if (tokenResponse.IsError)
            {
                AccessToken = tokenResponse.AsJson();
            }
            else
            {
                AccessToken = tokenResponse.AccessToken;
            }
        }
        else //client_credentials
        {
            var tokenResponse = await AccessService
                .RequestAccessTokenForClientCredentials(UdapClientState.ClientCredentialsTokenRequest);

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

    private async Task BuildAccessTokenRequest ()
    {
        if (UdapClientState.RegistrationDocument == null)
        {
            return;
        }

        if (string.IsNullOrEmpty(UdapClientState.RegistrationDocument?.ClientId))
        {
            TokenRequest1 = "Missing ClientId";
            return;
        }

        if (string.IsNullOrEmpty(UdapClientState.UdapMetadata?.TokenEndpoint))
        {
            TokenRequest1 = "Missing TokenEndpoint";
            return;
        }

        if (UdapClientState.Oauth2Flow == Oauth2FlowEnum.authorization_code)
        {
            UdapClientState.AuthorizationCodeTokenRequest = await AccessService
                .BuildRequestAccessTokenForAuthCode(
                    UdapClientState.RegistrationDocument.ClientId,
                    UdapClientState.UdapMetadata.TokenEndpoint,
                    Password
                    );
            
            var sb = new StringBuilder();
            sb.AppendLine("POST /token HTTP/1.1");
            sb.AppendLine($"Host: {UdapClientState.UdapMetadata?.AuthorizationEndpoint}");
            sb.AppendLine("Content-type: application/x-www-form-urlencoded");
            sb.AppendLine();
            sb.AppendLine("grant_type=authorization_code&");
            sb.AppendLine($"code=TODO&");
            sb.AppendLine($"client_assertion_type={OidcConstants.ClientAssertionTypes.JwtBearer}&");
            TokenRequest1 = sb.ToString();

            TokenRequest2 = $"client_assertion={UdapClientState.AuthorizationCodeTokenRequest?.ClientAssertion.Value}&\r\n";

            sb = new StringBuilder();
            sb.Append($"  udap={UdapConstants.UdapVersionsSupportedValue}&\r\n");
            TokenRequest3 = sb.ToString();
        }
        else  //client_credentials
        {
            UdapClientState.ClientCredentialsTokenRequest = await AccessService
                .BuildRequestAccessTokenForClientCredentials(
                    UdapClientState.RegistrationDocument.ClientId,
                    UdapClientState.UdapMetadata.TokenEndpoint,
                    Password);

            var sb = new StringBuilder();
            sb.AppendLine("POST /token HTTP/1.1");
            sb.AppendLine($"Host: {UdapClientState.UdapMetadata?.AuthorizationEndpoint}");
            sb.AppendLine("Content-type: application/x-www-form-urlencoded");
            sb.AppendLine();
            sb.AppendLine("grant_type=client_credentials&");
            TokenRequest1 = sb.ToString();
            sb = new StringBuilder();
            
            sb.AppendLine($"client_assertion_type={OidcConstants.ClientAssertionTypes.JwtBearer}&");
            TokenRequest2 = sb.ToString();
            
            TokenRequest3 = $"client_assertion={UdapClientState.ClientCredentialsTokenRequest?.ClientAssertion.Value}&";
            
            sb = new StringBuilder();
            sb.Append($"udap={UdapConstants.UdapVersionsSupportedValue}&\r\n");
            TokenRequest4 = sb.ToString();
        }
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
        sb.AppendLine($"\t client_id={UdapClientState.RegistrationDocument?.ClientId}&");
        sb.AppendLine($"\t scope= {UdapClientState.RegistrationDocument?.Scope}&");
        sb.AppendLine($"\t redirect_uri={UdapClientState.RegistrationDocument?.RedirectUris.FirstOrDefault()} HTTP/1.1");
        sb.AppendLine($"Host: {UdapClientState.UdapMetadata?.AuthorizationEndpoint}");

        AuthorizeRequest = sb.ToString();
    }

    private async Task GetAccessCode()
    {
        var url = new RequestUrl(UdapClientState.UdapMetadata?.AuthorizationEndpoint).CreateAuthorizeUrl(
            clientId: UdapClientState.RegistrationDocument?.ClientId,
            responseType: "code", 
            state: CryptoRandom.CreateUniqueId(),
            scope: UdapClientState.RegistrationDocument?.Scope,
            redirectUri: UdapClientState.RegistrationDocument?.RedirectUris.First());


        UdapClientState.AccessCodeRequestResult = await AccessService.Get(url);
    }
}
