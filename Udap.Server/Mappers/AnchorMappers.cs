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
    public static class AnchorMappers
    {
        static AnchorMappers()
        {
            Mapper = new MapperConfiguration(cfg =>
                {
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
        public static Udap.Common.Models.Anchor ToModel(this Anchor entity)
        {
            return Mapper.Map<Udap.Common.Models.Anchor>(entity);
        }

        /// <summary>
        /// Maps a model to an entity.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        public static Anchor ToEntity(this Udap.Common.Models.Anchor model)
        {
            return Mapper.Map<Anchor>(model);
        }
    }

    public class AnchorMapperProfile : Profile
    {
        public AnchorMapperProfile()
        {
            CreateMap<Anchor, Udap.Common.Models.Anchor>(MemberList.Destination)
                .ConstructUsing(src => new Udap.Common.Models.Anchor())

                .ForMember(model => model.Community, opts =>
                    opts.MapFrom(entity => entity.Community.Name))

                .ForMember(model => model.CommunityId, opts =>
                    opts.MapFrom(entity => entity.CommunityId))

                .ForMember(model => model.Certificate, opts =>
                    opts.MapFrom(entity => entity.X509Certificate))

                .ReverseMap()

                .ForMember(entity => entity.X509Certificate, opts =>
                    opts.MapFrom(model => model.Certificate))

                .ForMember(entity => entity.Community, opts => opts.Ignore());

            
        }
    }
}
