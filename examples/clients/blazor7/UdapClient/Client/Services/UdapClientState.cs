#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using Microsoft.AspNetCore.Components;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Services;

/// <summary>
/// Persistence data
/// </summary>
public class UdapClientState : IAppState
{
    public UdapClientState() {}

    public string MetadataUrl { get; set; } = "https://fhirlabs.net/fhir/r4/.well-known/udap";

    public UdapMetadata? UdapMetadata { get; set; }
    
    public string SoftwareStatementBeforeEncoding { get; set; } = string.Empty;

    public UdapRegisterRequest? RegistrationRequest { get; set; }

    public Oauth2FlowEnum Oauth2Flow { get; set; } = Oauth2FlowEnum.client_credentials;

    public RegistrationDocument? RegistrationDocument { get; set; }
    
    public UdapClientCredentialsTokenRequest? ClientCredentialsTokenRequest { get; set; }

    public UdapAuthorizationCodeTokenRequest? AuthorizationCodeTokenRequest { get; set; }
    public AccessCodeRequestResult? AccessCodeRequestResult { get; set; }
   
    public LoginCallBackResult? LoginCallBackResult { get; set; }

    public void UpdateAccessTokens(ComponentBase source, TokenResponseModel? tokenResponseModel)
    {
        AccessTokens = tokenResponseModel;

        NotifyStateChanged();
    }

    public TokenResponseModel? AccessTokens { get; set; }

    public ClientStatus Status
    {
        get
        {
            if (AccessTokens == null)
            {
                return new ClientStatus(false, "Missing");
            }

            if (AccessTokens.IsError)
            {
                return new ClientStatus(false, "Error");
            }

            if (DateTime.UtcNow >= AccessTokens.ExpiresAt)
            {
                return new ClientStatus (false, "Expired");
            }

            var tokensList = new List<string>();

            if (!AccessTokens.AccessToken.IsNullOrEmpty())
            {
                tokensList.Add("Access");
            }
            if (!AccessTokens.IdentityToken.IsNullOrEmpty())
            {
                tokensList.Add("Identity");
            }
            if (!AccessTokens.RefreshToken.IsNullOrEmpty())
            {
                tokensList.Add("Refresh");
            }

            var statusMessage = string.Join(" | ", tokensList);

            return new ClientStatus(true, statusMessage);
        }

        set
        {

        }
    }

    /// <summary>
    /// String representation of UDAP 3.1 Authorization Code Flow
    /// </summary>
    public string AuthorizationCodeRequest { get; set; }

    public bool IsLocalStorageInit { get; set; }

    public event Action? StateChanged;

    private void NotifyStateChanged() => StateChanged?.Invoke();


}