#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AutoMapper;
using Udap.Server.Entities;

namespace Udap.Server.Mappers
{
    //TODO: check if this is the best way:: https://jimmybogard.com/automapper-usage-guidelines/
    public static class CommunityMapper
    {
        static CommunityMapper()
        {
            Mapper = new MapperConfiguration(cfg =>
                {
                    cfg.AddProfile<CommunityMapperProfile>();
                    cfg.AddProfile<AnchorMapperProfile>();
                })
                .CreateMapper();
        }

        internal static IMapper Mapper { get; }

        /// <summary>
        /// Maps an entity to a model.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <returns></returns>
        public static Common.Models.Community ToModel(this Community entity)
        {
            return Mapper.Map<Common.Models.Community>(entity);
        }

        /// <summary>
        /// Maps a model to an entity.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        public static Community ToEntity(this Common.Models.Community model)
        {
            return Mapper.Map<Community>(model);
        }
    }

    public class CommunityMapperProfile : Profile
    {
        public CommunityMapperProfile()
        {
            
            CreateMap<Community, Common.Models.Community>(MemberList.Destination)
                .ConstructUsing(src => new Common.Models.Community())
                .ReverseMap()
                ;
                
            AllowNullCollections = true;
            
        }
    }
}
