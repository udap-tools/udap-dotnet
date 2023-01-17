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

                
                
            CreateMap<ICollection<RootCertificate>, ICollection<ViewModel.RootCertificate>>()
                 .ConstructUsing(src =>
                     src.Select(rootCertificate => new ViewModel.RootCertificate()
                     {
                         Id = rootCertificate.Id,
                         CommunityId = rootCertificate.CommunityId,
                         Name = rootCertificate.Name,
                         Url = rootCertificate.Url,
                         Thumbprint = rootCertificate.Thumbprint,
                         BeginDate = rootCertificate.BeginDate,
                         EndDate = rootCertificate.EndDate,
                         Enabled = rootCertificate.Enabled,
                         Certificate = X509Certificate2.CreateFromPem(rootCertificate.X509Certificate),
                         
                     }).ToHashSet()
                 )
                 .ForAllMembers(opt => opt.Ignore());

            AllowNullCollections = true;
            
        }
    }
}
