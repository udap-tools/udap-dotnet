#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AutoMapper;
using Udap.Server.Entities;

namespace Udap.Server.Mappers;

public static class TieredClientMapper
{
    static TieredClientMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
        {
            cfg.AddProfile<TieredClientMapperProfile>();
        })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static Common.Models.TieredClient ToModel(this TieredClient? entity)
    {
        return Mapper.Map<Common.Models.TieredClient>(entity);
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static Entities.TieredClient ToEntity(this Common.Models.TieredClient model)
    {
        return Mapper.Map<Entities.TieredClient>(model);
    }
}

public class TieredClientMapperProfile : Profile
{
    public TieredClientMapperProfile()
    {
        CreateMap<Entities.TieredClient, Common.Models.TieredClient>(MemberList.Destination)
            .ConstructUsing(src => new Common.Models.TieredClient())
            .ReverseMap()
            ;
    }
}