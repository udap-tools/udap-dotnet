#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Server.Storage.Stores;
using Udap.Server.Validation.Default;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
namespace Udap.Server.Configuration.DependencyInjection;

public static class IdentityServerBuilderExtensionsAdditional
{
    /// <summary>
    /// Adds support for client authentication using JWT bearer assertions.
    /// </summary>
    /// <param name="services">IServiceCollection</param>
    /// <returns></returns>
    public static IUdapServiceBuilder AddUdapJwtBearerClientAuthentication(this IUdapServiceBuilder builder)
    {
        builder.Services.TryAddTransient<IReplayCache, DefaultReplayCache>();
        builder.Services.AddTransient<ISecretParser, UdapJwtBearerClientAssertionSecretParser>();
        builder.Services.AddTransient<ISecretValidator, UdapJwtSecretValidator>();

        return builder;
    }

    /// <summary>
    /// Adds a UdapClientRegistrationStore.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="services">IServiceCollection</param>
    /// <returns></returns>
    public static IUdapServiceBuilder AddUdapClientRegistrationStore<T>(this IUdapServiceBuilder builder)
        where T : class, IUdapClientRegistrationStore
    {
        builder.Services.AddScoped<IUdapClientRegistrationStore, T>();

        // Todo: Opportunity to add validation in pattern with other Identity Store techniques
        //builder.Services.TryAddTransient(typeof(T));
        //builder.Services.AddTransient<IUdapClientRegistrationStore, ValidatingUdapClientRegistrationStore<T>>();

        return builder;
    }
}

