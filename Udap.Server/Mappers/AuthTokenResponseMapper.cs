#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AutoMapper;
using Udap.Client.Authentication;

namespace Udap.Server.Mappers;
public static class AuthTokenResponseMapper
{
    static AuthTokenResponseMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<AuthTokenResponseMapperProfile>();
            })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps a <see cref="OAuthTokenResponse"/> to a <see cref="Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse"/>.
    /// </summary>
    /// <param name="entity">The OAuthTokenResponse.</param>
    /// <returns></returns>
    public static Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse ToMSAuthTokenResponse(this OAuthTokenResponse response)
    {
        return Mapper.Map<Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse>(response);
    }

    /// <summary>
    /// Maps a <see cref="Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse"/> to a <see cref="OAuthTokenResponse"/>.
    /// </summary>
    /// <param name="response">The OAuthTokenResponse.</param>
    /// <returns></returns>
    public static OAuthTokenResponse ToClientAuthTokenResponse(this Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse response)
    {
        return Mapper.Map<OAuthTokenResponse>(response);
    }
}

public class AuthTokenResponseMapperProfile : Profile
{
    public AuthTokenResponseMapperProfile()
    {
        CreateMap<OAuthTokenResponse, Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse>()
            .ConstructUsing((src, context) =>
            {
                if (src.Error != null)
                {
                    return Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse.Failed(src.Error);
                }
                else
                {
                    return Microsoft.AspNetCore.Authentication.OAuth.OAuthTokenResponse.Success(src.Response);
                }
            });
    }
}
