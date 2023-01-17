#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AutoMapper;
using Udap.CA.Entities;

namespace Udap.CA.Mappers;

public static class AnchorMapper
{
    static AnchorMapper()
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
    public static ViewModel.Anchor ToModel(this Anchor entity)
    {
        return Mapper.Map<ViewModel.Anchor>(entity);
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static Anchor ToEntity(this ViewModel.Anchor model)
    {
        return Mapper.Map<Anchor>(model);
    }
}

public class AnchorMapperProfile : Profile
{
    public AnchorMapperProfile()
    {
        CreateMap<Anchor, ViewModel.Anchor>(MemberList.Destination)
            .ConstructUsing(src => new ViewModel.Anchor())

            .ForMember(model => model.RootCertificateId, opts =>
                opts.MapFrom(entity => entity.RootCertificateId))

            .ForMember(model => model.Certificate, opts =>
                opts.MapFrom(entity => entity.X509Certificate))

            .ReverseMap()

            .ForMember(entity => entity.X509Certificate, opts =>
                opts.MapFrom(model => model.Certificate))

            .ForMember(entity => entity.RootCertificate, opts => opts.Ignore());


    }
}

