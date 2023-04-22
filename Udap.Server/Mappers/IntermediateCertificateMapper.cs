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

namespace Udap.Server.Mappers;

public static class IntermediateCertificateMapper
{
    static IntermediateCertificateMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
        {
            cfg.AddProfile<IntermediateCertificateMapperProfile>();
        })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static Udap.Common.Models.Intermediate ToModel(this Intermediate entity)
    {
        return Mapper.Map<Udap.Common.Models.Intermediate>(entity);
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static Intermediate ToEntity(this Udap.Common.Models.Intermediate model)
    {
        return Mapper.Map<Intermediate>(model);
    }
}

public class IntermediateCertificateMapperProfile : Profile
{
    public IntermediateCertificateMapperProfile()
    {
        CreateMap<Intermediate, Udap.Common.Models.Intermediate>(MemberList.Destination)
            .ConstructUsing(src => new Udap.Common.Models.Intermediate())


            .ForMember(model => model.Certificate, opts =>
                opts.MapFrom(entity => entity.X509Certificate))

            .ReverseMap()

            .ForMember(entity => entity.X509Certificate, opts =>
                opts.MapFrom(model => model.Certificate));
    }
}

