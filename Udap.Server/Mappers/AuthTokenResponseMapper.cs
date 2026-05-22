#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Authentication;

namespace Udap.Server.Mappers;

public static class AuthTokenResponseMapper
{
    /// <summary>
    /// Maps a <see cref="OAuthTokenResponse"/> to a <see cref="Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse"/>.
    /// </summary>
    /// <returns></returns>
    public static Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse ToMSAuthTokenResponse(this OAuthTokenResponse response)
    {
        if (response.Error != null)
        {
            return Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse.Failed(response.Error);
        }

        if (response.Response != null)
        {
            return Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse.Success(response.Response);
        }

        return Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse.Failed(new Exception("Unknown"));
    }
}
