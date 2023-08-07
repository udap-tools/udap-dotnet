#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Common.Certificates;
using Udap.Server.Infrastructure.Clock;
using Udap.Server.Registration;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
namespace Microsoft.Extensions.DependencyInjection;

public static class UdapConfigurationServiceCollectionExtensions
{
   
    /// <summary>
    /// Register a <see cref="UdapDynamicClientRegistrationEndpoint"/> and a
    /// <see cref="UdapDynamicClientRegistrationValidator"/>.
    /// Remember to supply a IUdapClientRegistrationStore to access the certificate anchors
    /// and storage process for new client registrations.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddUdapServerConfiguration(this IServiceCollection services)
    {
        services.AddScoped<UdapDynamicClientRegistrationEndpoint>();
#if NET8_0_OR_GREATER
        services.TryAddTransient<IClock, DefaultClock>();
#else
        services.TryAddTransient<IClock, LegacyClock>();
#endif
        services.TryAddTransient<IUdapDynamicClientRegistrationValidator, UdapDynamicClientRegistrationValidator>();
        services.TryAddSingleton<TrustChainValidator>();

        return services;
    }
    

    /// <summary>
    /// Register a <see cref="UdapDynamicClientRegistrationEndpoint"/> and a
    /// <see cref="UdapDynamicClientRegistrationValidator"/>.
    /// Remember to supply a IUdapClientRegistrationStore to access the certificate anchors
    /// and storage process for new client registrations.
    /// </summary>
    /// <returns></returns>
    public static IIdentityServerBuilder AddUdapServerConfiguration(this IIdentityServerBuilder builder)
    {
        builder.Services.AddUdapServerConfiguration();

        return builder;
    }
}