#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Server.Storage.Stores;
using Udap.Server.Validation.Default;

namespace Udap.Server.Configuration.DependencyInjection.BuilderExtensions;

public static class IdentityServerBuilderExtensionsAdditional
{
    /// <summary>
    /// Adds support for client authentication using JWT bearer assertions.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <returns></returns>
    public static IIdentityServerBuilder AddUdapJwtBearerClientAuthentication(this IIdentityServerBuilder builder)
    {
        builder.Services.TryAddTransient<IReplayCache, DefaultReplayCache>();
        builder.AddSecretParser<UdapJwtBearerClientAssertionSecretParser>();
        builder.AddSecretValidator<UdapJwtSecretValidator>();

        return builder;
    }

    /// <summary>
    /// Adds a UdapClientRegistrationStore.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="builder">The builder.</param>
    /// <returns></returns>
    public static IIdentityServerBuilder AddUdapClientRegistrationStore<T>(this IIdentityServerBuilder builder)
        where T : class, IUdapClientRegistrationStore
    {
        builder.Services.AddTransient<IUdapClientRegistrationStore, T>();

        // Todo: Oportunity to add validation in pattern with other Identity Store techniques
        //builder.Services.TryAddTransient(typeof(T));
        //builder.Services.AddTransient<IUdapClientRegistrationStore, ValidatingUdapClientRegistrationStore<T>>();

        return builder;
    }
}

