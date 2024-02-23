#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AutoMapper;
using Udap.Model.Access;
using UdapEd.Shared.Model;

namespace UdapEd.Shared.Mappers;
public static class UdapAuthorizationCodeTokenRequestMapper
{
    static UdapAuthorizationCodeTokenRequestMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<UdapAuthorizationCodeTokenRequestProfile>();
                cfg.AddProfile<ClientAssertionProfile>();
            })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps a <see cref="UdapAuthorizationCodeTokenRequest"/> to a <see cref="UdapAuthorizationCodeTokenRequestModel"/>.
    /// </summary>
    /// <param name="request">The UdapAuthorizationCodeTokenRequest.</param>
    /// <returns></returns>
    public static UdapAuthorizationCodeTokenRequestModel ToModel(this UdapAuthorizationCodeTokenRequest request)
    {
        return Mapper.Map<UdapAuthorizationCodeTokenRequestModel>(request);
    }
}

public class UdapAuthorizationCodeTokenRequestProfile : Profile
{
    public UdapAuthorizationCodeTokenRequestProfile()
    {
        CreateMap<UdapAuthorizationCodeTokenRequest, UdapAuthorizationCodeTokenRequestModel>();
    }
}