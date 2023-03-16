using System.Security.Cryptography.X509Certificates;
using AutoMapper;
using Udap.Common.Models;
using Udap.Util.Extensions;

namespace Udap.Idp.Admin.Mappers;

public class AutoMapping : Profile
{
    public AutoMapping() {
        CreateMap<Community, ViewModel.Community>()
            .ReverseMap();

        CreateMap<Anchor, ViewModel.Anchor>(MemberList.Destination)
            .ConstructUsing(src => new ViewModel.Anchor())
            .ForMember(vm => vm.Certificate, opts =>
                opts.MapFrom(model =>
                    X509Certificate2.CreateFromPem(model.Certificate)))
            .ReverseMap()
            .ForMember(entity => entity.Certificate, opts => 
                opts.MapFrom(model =>
                    model.Certificate.ToPemFormat()));


        CreateMap<IntermediateCertificate, ViewModel.RootCertificate>(MemberList.Destination)
            .ConstructUsing(src => new ViewModel.RootCertificate())
            .ForMember(vm => vm.Certificate, opts =>
                opts.MapFrom(model =>
                    X509Certificate2.CreateFromPem(model.Certificate)))
            .ReverseMap()
            .ForMember(entity => entity.Certificate, opts =>
                opts.MapFrom(model =>
                    model.Certificate.ToPemFormat()));


        CreateMap<Certification, ViewModel.Certification>()
            .ReverseMap();

        CreateMap<IssuedCertificate, ViewModel.IssuedCertificate>()
            .ReverseMap();
    }
}

