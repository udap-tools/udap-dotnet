using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using UdapEd.Shared.Model;

namespace UdapEd.Client.Services;

public interface IAppState
{
    string MetadataUrl { get; }
    
    UdapMetadata? UdapMetadata { get; }

    string SoftwareStatementBeforeEncoding { get; }

    UdapRegisterRequest? UdapRegistrationRequest { get; }

    Oauth2FlowEnum Oauth2Flow { get; }

    RegistrationDocument? RegistrationDocument { get; }

    UdapClientCredentialsTokenRequest? ClientCredentialsTokenRequest { get; }

    UdapAuthorizationCodeTokenRequest? AuthorizationCodeTokenRequest { get; }
    AccessCodeRequestResult? AccessCodeRequestResult { get;  }

    LoginCallBackResult? LoginCallBackResult { get;  }

    TokenResponseModel? AccessTokens { get;  }

    ClientStatus Status { get; }

    AuthorizationCodeRequest?AuthorizationCodeRequest { get; }
}
