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
public static class UdapClientCredentialsTokenRequestMapper
{
    static UdapClientCredentialsTokenRequestMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<UdapClientCredentialsTokenRequestProfile>();
                cfg.AddProfile<ClientAssertionProfile>();
            })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps a <see cref="UdapClientCredentialsTokenRequest"/> to a <see cref="UdapClientCredentialsTokenRequestModel"/>.
    /// </summary>
    /// <param name="request">The UdapClientCredentialsTokenRequest.</param>
    /// <returns></returns>
    public static UdapClientCredentialsTokenRequestModel ToModel(this UdapClientCredentialsTokenRequest request)
    {
        return Mapper.Map<UdapClientCredentialsTokenRequestModel>(request);
    }
}

public class UdapClientCredentialsTokenRequestProfile : Profile
{
    public UdapClientCredentialsTokenRequestProfile()
    {
        CreateMap<UdapClientCredentialsTokenRequest, UdapClientCredentialsTokenRequestModel>();
    }
}