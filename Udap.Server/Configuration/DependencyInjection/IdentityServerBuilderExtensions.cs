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
using Microsoft.Extensions.Options;
using Udap.Server;
using Udap.Server.Configuration;
using Udap.Server.DbContexts;
using Udap.Server.Extensions;
using Udap.Server.Options;
using Udap.Server.Registration;
using static Udap.Server.Constants;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
namespace Microsoft.Extensions.DependencyInjection;


public static class IdentityServerBuilderExtensions
{
    public static IIdentityServerBuilder AddUdapServer(
        this IIdentityServerBuilder builder,
        Action<ServerSettings> setupAction,
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

        builder.AddUdapJwtBearerClientAuthentication()
            .AddUdapDiscovery(baseUrl)
            .AddUdapServerConfiguration();

        return builder;
    }


    /// <summary>
    /// Include "registration_endpoint" in the Identity Server, discovery document
    /// (.well-known/openid-configuration)
    /// 
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="baseUrl"></param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    private static IIdentityServerBuilder AddUdapDiscovery(
        this IIdentityServerBuilder builder,
       string? baseUrl = null)
    {

        if (baseUrl == null)
        {
            baseUrl = Environment.GetEnvironmentVariable("UdapIdpBaseUrl");

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

