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
using Udap.Server.Extensions;
using static Udap.Server.Constants;

namespace Udap.Server.Configuration
{
    public static class IdentityServerBuilderExtensions
    {
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
        public static IIdentityServerBuilder AddUdapDiscovery(
            this IIdentityServerBuilder builder, 
           string? registrationEndpoint = null )
        {

            if (registrationEndpoint == null)
            {
                bool isInDockerContainer = (Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true");
                var baseUrl = "http://localhost:8080";

                if (!isInDockerContainer)
                {
                    baseUrl = $"{Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Split(';').First()}";
                }

                if (string.IsNullOrEmpty(baseUrl))
                {
                    throw new Exception(
                        "Missing ASPNETCORE_URLS environment variable.  Or missing registrationEndpoint parameter");
                }
                
                registrationEndpoint = $"{baseUrl}" +
                                       $"{ProtocolRoutePaths.Register.EnsureLeadingSlash()}" ;
            }

            
            builder.Services.Configure<IdentityServerOptions>(options =>
                options.Discovery.CustomEntries.Add(
                    OidcConstants.Discovery.RegistrationEndpoint,
                    registrationEndpoint));

            return builder.AddEndpoint<UdapDiscoveryEndpoint>(
                EndpointNames.Discovery,
                ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash());
        }
    }
}
