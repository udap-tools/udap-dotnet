#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Tefca.Model;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers TEFCA authorization extension deserializers so that
    /// the UDAP server can deserialize and validate TEFCA-specific
    /// extension objects (e.g., tefca_ias) from client assertion JWTs.
    /// </summary>
    public static IServiceCollection AddUdapTefcaExtensions(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationExtensionDeserializer, TefcaIasDeserializer>();

        return services;
    }
}
