#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Common.Certificates;
using Udap.Server.Configuration;

namespace Udap.Server.Registration;

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
    /// <param name="services"></param>
    /// <returns></returns>
    public static IIdentityServerBuilder AddUdapServerConfiguration(this IIdentityServerBuilder builder)
    {
        builder.Services.AddUdapServerConfiguration();

        return builder;
    }
}