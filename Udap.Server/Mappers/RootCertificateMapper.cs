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

public static class RootCertificateMapper
{
    static RootCertificateMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
        {
            cfg.AddProfile<RootCertificateMapperProfile>();
        })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static Udap.Common.Models.IntermediateCertificate ToModel(this IntermediateCertificate entity)
    {
        return Mapper.Map<Udap.Common.Models.IntermediateCertificate>(entity);
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static IntermediateCertificate ToEntity(this Udap.Common.Models.IntermediateCertificate model)
    {
        return Mapper.Map<IntermediateCertificate>(model);
    }
}

public class RootCertificateMapperProfile : Profile
{
    public RootCertificateMapperProfile()
    {
        CreateMap<IntermediateCertificate, Udap.Common.Models.IntermediateCertificate>(MemberList.Destination)
            .ConstructUsing(src => new Udap.Common.Models.IntermediateCertificate())


            .ForMember(model => model.Certificate, opts =>
                opts.MapFrom(entity => entity.X509Certificate))

            .ReverseMap()

            .ForMember(entity => entity.X509Certificate, opts =>
                opts.MapFrom(model => model.Certificate));

    }
}

