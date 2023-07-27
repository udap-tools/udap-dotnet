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
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Server;
using Udap.Server.Configuration;
using Udap.Server.DbContexts;
using Udap.Server.Extensions;
using Udap.Server.Mappers;
using Udap.Server.Options;
using Udap.Server.Stores;
using static Udap.Server.Constants;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions to enable UDAP Server.
/// </summary>
public static class IdentityServerBuilderExtensions
{
    /// <summary>
    /// Extend Identity Server with <see cref="Udap.Server"/>.
    ///
    /// /// Include "registration_endpoint" in the Identity Server, discovery document
    /// (.well-known/openid-configuration)
    /// 
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="setupAction">Apply <see cref="ServerSettings"/></param>
    /// <param name="storeOptionAction">Apply <see cref="UdapConfigurationStoreOptions"/></param>
    /// <param name="baseUrl">Supply the baseUrl or set UdapIdpBaseUrl environment variable.</param>
    /// <returns></returns>
    /// <exception cref="Exception">If missing baseUrl and UdapIdpBaseUrl environment variable.</exception>
    public static IIdentityServerBuilder AddUdapServer(
        this IIdentityServerBuilder builder,
        Action<ServerSettings> setupAction,
        Action<UdapClientOptions>? clientOptionAction = null,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null,
        string? baseUrl = null)
    {
        builder.Services.Configure(setupAction);
        if (clientOptionAction != null)
        {
            builder.Services.Configure(clientOptionAction);
            builder.Services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<UdapClientOptions>>().Value);
        }
        builder.Services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<ServerSettings>>().Value);
        builder.AddUdapServer(baseUrl);
        builder.AddUdapConfigurationStore<UdapDbContext>(storeOptionAction);

        return builder;
    }

    /// <summary>
    /// Extend Identity Server with <see cref="Udap.Server"/>.
    ///
    /// Include "registration_endpoint" in the Identity Server, discovery document
    /// (.well-known/openid-configuration)
    /// 
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="setupAction">Apply <see cref="ServerSettings"/></param>
    /// <param name="storeOptionAction">Apply <see cref="UdapConfigurationStoreOptions"/></param>
    /// <param name="baseUrl">Supply the baseUrl or set UdapIdpBaseUrl environment variable.</param>
    /// <returns></returns>
    /// <exception cref="Exception">If missing baseUrl and UdapIdpBaseUrl environment variable.</exception>
    public static IIdentityServerBuilder AddUdapServerAsIdentityProvider(
        this IIdentityServerBuilder builder,
        Action<ServerSettings>? setupAction = null,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null,
        string? baseUrl = null)
    {
        if (setupAction != null)
        {
            builder.Services.Configure(setupAction);
        }

        builder.Services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<ServerSettings>>().Value);
        builder.AddRegistrationEndpointToOpenIdConnectMetadata(baseUrl);
        builder.AddUdapServerConfiguration();
        builder.AddUdapConfigurationStore<UdapDbContext>(storeOptionAction);
        builder.AddUdapJwtBearerClientAuthentication();

        return builder;
    }

    /// <summary>
    /// Not used for a typical server.  Exposed for testing.
    ///
    /// Include "registration_endpoint" in the Identity Server, discovery document
    /// (.well-known/openid-configuration)
    /// 
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="baseUrl">Supply the baseUrl or set UdapIdpBaseUrl environment variable.</param>
    /// <returns></returns>
    /// <exception cref="Exception">If missing baseUrl and UdapIdpBaseUrl environment variable.</exception>
    public static IIdentityServerBuilder AddUdapServer(
        this IIdentityServerBuilder builder,
        string? baseUrl = null,
        string? resourceServerName = null)//Todo refactor resourceServerName out everywhere
    {

        builder.Services.AddSingleton<IPrivateCertificateStore>(sp =>
            new IssuedCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                sp.GetRequiredService<ILogger<IssuedCertificateStore>>(),
                resourceServerName ?? "Udap.Auth.Server"));

        // TODO: TrustAnchor has to be singleton because
        // builder.AddOAuth<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>
        // forces IOptionsMonitor<TieredOAuthAuthenticationOptions> to be singleton.
        // So I would have to get very creative in creating a background thread to keep a monitor
        // on the database.  .... Future
        builder.Services.TryAddSingleton<ITrustAnchorStore>(sp =>
        {
            using var scope = sp.CreateScope();
            using var db =  scope.ServiceProvider.GetService<IUdapDbContext>();
            
            if (db == null)            {
                return new TrustAnchorStore(new List<Anchor>());  //Some unit tests don't care about this. //TODO

            }
            return new TrustAnchorStore(db.Anchors.Select(a => a.ToModel()).ToList());
        });


        builder.AddUdapJwtBearerClientAuthentication()
            .AddRegistrationEndpointToOpenIdConnectMetadata(baseUrl)
            .AddUdapDiscovery()
            .AddUdapServerConfiguration();

        return builder;
    }
    
    //
    // This just adds the registration endpoint to /.well-known/openid-configuration
    //
    private static IIdentityServerBuilder AddRegistrationEndpointToOpenIdConnectMetadata(
        this IIdentityServerBuilder builder,
       string? baseUrl = null)
    {

        if (baseUrl == null)
        {
            baseUrl = Environment.GetEnvironmentVariable("UdapIdpBaseUrl");

            if (string.IsNullOrEmpty(baseUrl))
            {
                throw new Exception(
                    "Missing ASPNETCORE_URLS environment variable.  Or missing baseUrl parameter in AddUdapServer extension method.");
            }
        }

        baseUrl = $"{baseUrl.EnsureTrailingSlash()}{ProtocolRoutePaths.Register}";

        builder.Services.Configure<IdentityServerOptions>(options =>
            options.Discovery.CustomEntries.Add(
                OidcConstants.Discovery.RegistrationEndpoint,
                baseUrl));

        return builder;
    }

    private static IIdentityServerBuilder AddUdapDiscovery(
        this IIdentityServerBuilder builder)
    {
        return builder.AddEndpoint<UdapDiscoveryEndpoint>(
            EndpointNames.Discovery,
            ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash());
    }
}

