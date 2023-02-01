using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Services;

public interface IAppState
{
    string MetadataUrl { get; }
    
    UdapMetadata? UdapMetadata { get; }

    string SoftwareStatementBeforeEncoding { get; }

    UdapRegisterRequest? RegistrationRequest { get; }

    Oauth2FlowEnum Oauth2Flow { get; }

    RegistrationDocument? RegistrationDocument { get; }

    UdapClientCredentialsTokenRequest? ClientCredentialsTokenRequest { get; }

    UdapAuthorizationCodeTokenRequest? AuthorizationCodeTokenRequest { get; }
    AccessCodeRequestResult? AccessCodeRequestResult { get;  }

    LoginCallBackResult? LoginCallBackResult { get;  }

    TokenResponseModel? AccessTokens { get;  }

    ClientStatus Status { get; }

    /// <summary>
    /// String representation of UDAP 3.1 Authorization Code Flow
    /// </summary>
    string AuthorizationCodeRequest { get; }
}
