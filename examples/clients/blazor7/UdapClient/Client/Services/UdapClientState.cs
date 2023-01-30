#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Services;

public class UdapClientState
{
    public UdapClientState() {}

    public string MetadataUrl { get; set; } = "https://fhirlabs.net/fhir/r4/.well-known/udap";

    public UdapMetadata? UdapMetadata { get; set; }
    
    public string SoftwareStatementBeforeEncoding { get; set; } = string.Empty;

    public UdapRegisterRequest? RegistrationRequest { get; set; }

    public Oauth2FlowEnum Oauth2Flow { get; set; } = Oauth2FlowEnum.client_credentials;

    public RegistrationDocument? RegistrationDocument { get; set; }
    

    public string? RegistrationClaims { get; set; }

    public UdapClientCredentialsTokenRequest? ClientCredentialsTokenRequest { get; set; }

    public UdapAuthorizationCodeTokenRequest? AuthorizationCodeTokenRequest { get; set; }
    public AccessCodeRequestResult? AccessCodeRequestResult { get; set; }
   
    public LoginCallBackResult LoginCallBackResult { get; set; }

    private bool _isLocalStorageInit;

    public bool IsLocalStorageInit()
    {
        return _isLocalStorageInit;
    }

    public void LocalStorageInit()
    {
        _isLocalStorageInit = true;
    }
}