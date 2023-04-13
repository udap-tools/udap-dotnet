using System.Collections.Specialized;
using Udap.Model;
using Udap.Model.Registration;
using UdapEd.Shared.Model;

namespace UdapEd.Client.Services;

public interface IAppState
{
    string BaseUrl { get; }
    
    string Community { get; }

    OrderedDictionary BaseUrls { get; set; }

    UdapMetadata? UdapMetadata { get; }

    RawSoftwareStatementAndHeader SoftwareStatementBeforeEncoding { get; }

    UdapRegisterRequest? UdapRegistrationRequest { get; }
    Oauth2FlowEnum Oauth2Flow { get; }

    RegistrationDocument? RegistrationDocument { get; }


    UdapClientCredentialsTokenRequestModel? ClientCredentialsTokenRequest { get; }

    CertificateStatusViewModel? CertificateInfo { get; }
    
    UdapAuthorizationCodeTokenRequestModel? AuthorizationCodeTokenRequest { get; }

    AccessCodeRequestResult? AccessCodeRequestResult { get;  }

    LoginCallBackResult? LoginCallBackResult { get;  }

    TokenResponseModel? AccessTokens { get;  }

    ClientStatus Status { get; }

    AuthorizationCodeRequest?AuthorizationCodeRequest { get; }
}
