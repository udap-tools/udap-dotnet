#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using UdapEd.Shared.Model;
using UdapEd.Shared.Services;

namespace UdapEdAppMaui.Services;
internal class AccessService : IAccessService
{
    public Task<AccessCodeRequestResult?> Get(string authorizeQuery)
    {
        throw new NotImplementedException();
    }

    public Task<UdapAuthorizationCodeTokenRequestModel?> BuildRequestAccessTokenForAuthCode(AuthorizationCodeTokenRequestModel tokenRequestModel, string signingAlgorithm)
    {
        throw new NotImplementedException();
    }

    public Task<UdapClientCredentialsTokenRequestModel?> BuildRequestAccessTokenForClientCredentials(ClientCredentialsTokenRequestModel tokenRequestModel,
        string signingAlgorithm)
    {
        throw new NotImplementedException();
    }

    public Task<TokenResponseModel?> RequestAccessTokenForClientCredentials(UdapClientCredentialsTokenRequestModel request)
    {
        throw new NotImplementedException();
    }

    public Task<TokenResponseModel?> RequestAccessTokenForAuthorizationCode(UdapAuthorizationCodeTokenRequestModel request)
    {
        throw new NotImplementedException();
    }
}
