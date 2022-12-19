#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using AutoMapper;
using Udap.CA.Entities;

namespace Udap.CA.Mappers
{
    //TODO: check if this is the best way:: https://jimmybogard.com/automapper-usage-guidelines/
    public static class CommunityMapper
    {
        static CommunityMapper()
        {
            Mapper = new MapperConfiguration(cfg =>
                {
                    cfg.AddProfile<CommunityMapperProfile>();
                })
                .CreateMapper();
        }

        internal static IMapper Mapper { get; }

        /// <summary>
        /// Maps an entity to a model.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <returns></returns>
        public static ViewModel.Community ToViewModel(this Community entity)
        {
            return Mapper.Map<ViewModel.Community>(entity);
        }

        /// <summary>
        /// Maps a model to an entity.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        public static Community ToEntity(this ViewModel.Community model)
        {
            return Mapper.Map<Community>(model);
        }
    }

    public class CommunityMapperProfile : Profile
    {
        public CommunityMapperProfile()
        {

            CreateMap<Community, ViewModel.Community>(MemberList.Destination)
                .ConstructUsing(src => new ViewModel.Community())
                .ReverseMap();

                
                
            CreateMap<ICollection<Anchor>, ICollection<ViewModel.Anchor>>()
                 .ConstructUsing(src =>
                     // var dest = new HashSet<Model.Models.Anchor>();
                     src.Select(anchor => new ViewModel.Anchor()
                     {
                         Id = anchor.Id,
                         Subject = anchor.Subject,
                         SubjectAltName = anchor.SubjectAltName,
                         CertificateRevocation = anchor.CertificateRevocation,
                         CertificateAuthIssuerUri = anchor.CertificateAuthIssuerUri,
                         Thumbprint = anchor.Thumbprint,
                         BeginDate = anchor.BeginDate,
                         EndDate = anchor.EndDate,
                         Enabled = anchor.Enabled,
                         Certificate = X509Certificate2.CreateFromPem(anchor.X509Certificate),
                         RootCertificateId = anchor.RootCertificateId
                     }).ToHashSet()
                 )
                 .ForAllMembers(opt => opt.Ignore());

            AllowNullCollections = true;
            
        }
    }
}
