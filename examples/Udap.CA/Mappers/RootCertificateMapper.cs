#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AutoMapper;
using Udap.CA.Entities;
using Udap.Common;

namespace Udap.CA.Mappers;

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
    public static ViewModel.RootCertificate ToViewModel(this RootCertificate entity)
    {
        return Mapper.Map<ViewModel.RootCertificate>(entity);
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static RootCertificate ToEntity(this ViewModel.RootCertificate model)
    {
        return Mapper.Map<RootCertificate>(model);
    }
}

public class RootCertificateMapperProfile : Profile
{
    public RootCertificateMapperProfile()
    {
        CreateMap<RootCertificate, ViewModel.RootCertificate>(MemberList.Destination)
            .ConstructUsing(src => new ViewModel.RootCertificate())

            .ForMember(model => model.Certificate, opts =>
                opts.MapFrom(entity => X509Certificate2.CreateFromPem(entity.X509Certificate)))
            

            /*
             * .ForMember(model => model.Certificate, opts =>
                opts.MapFrom(entity => new X509Certificate2(
                    entity.Certificate,
                    entity.Secret,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable
                )))
             */

            .ReverseMap()

            .ForMember(entity => entity.RSAPrivateKey, opts =>
                opts.MapFrom(model =>
                    PemEncoding.WriteString(
                        PemLabels.RsaPrivateKey,
                        model.Certificate.Export(X509ContentType.Pkcs12, model.Secret))))

            .ForMember(entity => entity.X509Certificate, opts =>
                opts.MapFrom(model =>
                    PemEncoding.WriteString(
                        PemLabels.X509Certificate,
                        model.Certificate.Export(X509ContentType.Cert))));
        
        // model.Certificate.Export(X509ContentType.Pkcs12, model.Secret)));

    }
}

