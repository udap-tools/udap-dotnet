#region (c) 2024 Joseph Shook. All rights reserved.

// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */

#endregion

using UdapEd.Shared.Model;

namespace UdapEd.Shared.Services;

public interface IAccessService
{
    Task<AccessCodeRequestResult?> Get(string authorizeQuery);

    Task<UdapAuthorizationCodeTokenRequestModel?> BuildRequestAccessTokenForAuthCode(
        AuthorizationCodeTokenRequestModel tokenRequestModel,
        string signingAlgorithm);

    Task<UdapClientCredentialsTokenRequestModel?> BuildRequestAccessTokenForClientCredentials(
        ClientCredentialsTokenRequestModel tokenRequestModel,
        string signingAlgorithm);

    Task<TokenResponseModel?> RequestAccessTokenForClientCredentials(UdapClientCredentialsTokenRequestModel request);
    Task<TokenResponseModel?> RequestAccessTokenForAuthorizationCode(UdapAuthorizationCodeTokenRequestModel request);
}