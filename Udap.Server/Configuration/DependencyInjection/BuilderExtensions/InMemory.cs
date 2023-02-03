using Microsoft.Extensions.DependencyInjection;
using Udap.Common.Models;
using Udap.Server.Stores.InMemory;


namespace Udap.Server.Configuration.DependencyInjection.BuilderExtensions;
public static class InMemory
{
    public static IIdentityServerBuilder AddInMemoryUdapCertificates(
        this IIdentityServerBuilder builder,
        IEnumerable<Community> communities,
        IEnumerable<RootCertificate> rootCertificates)
    {
        builder.Services.AddSingleton(communities);
        builder.Services.AddSingleton(rootCertificates);
        builder.AddUdapClientRegistrationStore<InMemoryUdapClientRegistrationStore>();
        

        return builder;
    }
}
