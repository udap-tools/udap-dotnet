using System.Collections.Specialized;
using Udap.Model;
using Udap.Model.Registration;
using UdapEd.Client.Shared;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;

namespace UdapEd.Client.Services;

public interface IAppState
{
    string BaseUrl { get; }
    
    string Community { get; }

    OrderedDictionary BaseUrls { get; set; }

    public MetadataVerificationModel? MetadataVerificationModel { get; }

    RawSoftwareStatementAndHeader SoftwareStatementBeforeEncoding { get; }

    UdapRegisterRequest? UdapRegistrationRequest { get; }
    Oauth2FlowEnum Oauth2Flow { get; }

    RegistrationDocument? RegistrationDocument { get; }


    UdapClientCredentialsTokenRequestModel? ClientCredentialsTokenRequest { get; }

    CertificateStatusViewModel? ClientCertificateInfo { get; }
    
    UdapAuthorizationCodeTokenRequestModel? AuthorizationCodeTokenRequest { get; }

    AccessCodeRequestResult? AccessCodeRequestResult { get;  }

    LoginCallBackResult? LoginCallBackResult { get;  }

    TokenResponseModel? AccessTokens { get;  }

    ClientStatus Status { get; }

    AuthorizationCodeRequest?AuthorizationCodeRequest { get; }

    ClientRegistrations? ClientRegistrations { get; }

    ClientHeaders? ClientHeaders { get; }
}
