#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Configuration;
using IdentityModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Udap.Server.Configuration.DependencyInjection;
using Udap.Server.Configuration.DependencyInjection.BuilderExtensions;
using Udap.Server.DbContexts;
using Udap.Server.Extensions;
using Udap.Server.Options;
using Udap.Server.Registration;
using static Udap.Server.Constants;

namespace Udap.Server.Configuration
{
    public static class IdentityServerBuilderExtensions
    {
        public static IIdentityServerBuilder AddUdapServer(
            this IIdentityServerBuilder builder,
            Action<ServerSettings> setupAction = null,
            Action<UdapConfigurationStoreOptions>? storeOptionAction = null,
            string? baseUrl = null)
        {
            builder.Services.Configure(setupAction);
            builder.Services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<ServerSettings>>().Value);
            builder.AddUdapServer(baseUrl);
            builder.AddUdapConfigurationStore<UdapDbContext>(storeOptionAction);

            return builder;
        }

        public static IIdentityServerBuilder AddUdapServer(
            this IIdentityServerBuilder builder,
            string? baseUrl = null)
        {
            
            builder.AddUdapJwtBearerClientAuthentication();
            builder.AddUdapDiscovery(baseUrl);
            builder.AddUdapServerConfiguration();

            return builder;
        }


        /// <summary>
        /// Include "registration_endpoint" in the Identity Server, discovery document
        /// (.well-known/openid-configuration)
        /// 
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="environment"></param>
        /// <param name="registrationEndpoint"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        private static IIdentityServerBuilder AddUdapDiscovery(
            this IIdentityServerBuilder builder, 
           string? baseUrl = null )
        {

            if (baseUrl == null)
            {
                baseUrl = Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Split(';').First();

                if (string.IsNullOrEmpty(baseUrl))
                {
                    throw new Exception(
                        "Missing ASPNETCORE_URLS environment variable.  Or missing registrationEndpoint parameter");
                }

                baseUrl = $"{baseUrl}" +
                              $"{ProtocolRoutePaths.Register.EnsureLeadingSlash()}";
            }


            builder.Services.Configure<IdentityServerOptions>(options =>
                options.Discovery.CustomEntries.Add(
                    OidcConstants.Discovery.RegistrationEndpoint,
                    baseUrl));

            return builder.AddEndpoint<UdapDiscoveryEndpoint>(
                EndpointNames.Discovery,
                ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash());
        }
    }
}
