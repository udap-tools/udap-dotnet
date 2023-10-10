#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using System.Collections.Specialized;
using Microsoft.AspNetCore.Components;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;

namespace UdapEd.Client.Services;

/// <summary>
/// Persistence data
/// </summary>
public class UdapClientState : IAppState
{
    public UdapClientState() {}

    public string BaseUrl { get; set; } = "https://fhirlabs.net/fhir/r4/.well-known/udap";

    public string Community { get; set; }

    public OrderedDictionary BaseUrls { get; set; }

    public MetadataVerificationModel? MetadataVerificationModel { get; set; }

    public RawSoftwareStatementAndHeader? SoftwareStatementBeforeEncoding { get; set; }

    public UdapRegisterRequest? UdapRegistrationRequest { get; set; }

    public Oauth2FlowEnum Oauth2Flow { get; set; } = Oauth2FlowEnum.client_credentials;

    public RegistrationDocument? RegistrationDocument { get; set; }
    
    public UdapClientCredentialsTokenRequestModel? ClientCredentialsTokenRequest { get; set; }

    public UdapAuthorizationCodeTokenRequestModel? AuthorizationCodeTokenRequest { get; set; }

    public CertificateStatusViewModel? ClientCertificateInfo { get; set; }

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

            if (!string.IsNullOrEmpty(AccessTokens.AccessToken))
            {
                tokensList.Add("Access");
            }
            if (!string.IsNullOrEmpty(AccessTokens.IdentityToken))
            {
                tokensList.Add("Identity");
            }
            if (!string.IsNullOrEmpty(AccessTokens.RefreshToken))
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
    public AuthorizationCodeRequest? AuthorizationCodeRequest { get; set; }

    public ClientRegistrations? ClientRegistrations { get; set; }
    public ClientHeaders? ClientHeaders { get; set; }

    public event Action? StateChanged;

    private void NotifyStateChanged() => StateChanged?.Invoke();


}