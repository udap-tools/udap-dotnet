#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.ResponseHandling;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Server.Configuration;
using Udap.Server.Configuration.DependencyInjection;
using Udap.Server.ResponseHandling;
using Udap.Server.Security.Authentication.TieredOAuth;
using Udap.Server.Storage.DbContexts;
using Udap.Server.Storage.Mappers;
using Udap.Server.Storage.Options;
using Udap.Server.Storage.Stores;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Extensions to enable UDAP Server.
/// </summary>
public static class UdapServerServiceCollectionExtensions
{

    /// <summary>
    /// Creates a builder.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <returns></returns>
    public static IUdapServiceBuilder AddUdapServerBuilder(this IServiceCollection services)
    {
        return new UdapServiceBuilder(services);
    }

    /// <summary>
    /// Extend Identity Server with <see cref="Udap.Server"/>.
    /// 
    /// /// Include "registration_endpoint" in the Identity Server, discovery document
    /// (.well-known/openid-configuration)
    /// 
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="services"></param>
    /// <param name="serverSettingsAction">Apply <see cref="ServerSettings"/></param>
    /// <param name="clientOptionAction">Apply <see cref="UdapClientOptions"/></param>
    /// <param name="storeOptionAction">Apply <see cref="UdapConfigurationStoreOptions"/></param>
    /// <param name="baseUrl">Supply the baseUrl or set UdapIdpBaseUrl environment variable.</param>
    /// <returns></returns>
    /// <exception cref="Exception">If missing baseUrl and UdapIdpBaseUrl environment variable.</exception>
    public static IUdapServiceBuilder AddUdapServer(
        this IServiceCollection services,
        Action<ServerSettings> serverSettingsAction,
        Action<UdapClientOptions>? clientOptionAction = null,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null,
        string? baseUrl = null)
    {
        var builder = services.AddUdapServerBuilder();

        builder.Services.Configure(serverSettingsAction);
        if (clientOptionAction != null)
        {
            builder.Services.Configure(clientOptionAction);
        }

        builder.Services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<ServerSettings>>().Value);
        builder.Services.AddUdapServer(baseUrl);
        builder.AddUdapConfigurationStore<UdapDbContext>(storeOptionAction);

        return builder;
    }

    /// <summary>
    /// Not used for a typical server.  Exposed for testing.
    /// 
    /// Include "registration_endpoint" in the Identity Server, discovery document
    /// (.well-known/openid-configuration)
    /// 
    /// </summary>
    /// <param name="services"></param>
    /// <param name="baseUrl">Supply the baseUrl or set UdapIdpBaseUrl environment variable.</param>
    /// <returns></returns>
    /// <exception cref="Exception">If missing baseUrl and UdapIdpBaseUrl environment variable.</exception>
    public static IUdapServiceBuilder AddUdapServer(
        this IServiceCollection services,
        string? baseUrl = null,
        string? resourceServerName = null) //Todo refactor resourceServerName out everywhere
    {
        var builder = services.AddUdapServerBuilder();

        builder.AddPrivateFileStore(resourceServerName);

        builder.Services.TryAddSingleton<UdapClientDiscoveryValidator>();
        builder.Services.AddTransient<ITokenResponseGenerator, UdapTokenResponseGenerator>();

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

    /// <summary>
    /// Extend Identity Server with <see cref="Udap.Server"/>.
    ///
    /// Include "registration_endpoint" in the Identity Server, discovery document
    /// (.well-known/openid-configuration)
    /// 
    /// </summary>
    /// <param name="services"></param>
    /// <param name="setupAction">Apply <see cref="ServerSettings"/></param>
    /// <param name="storeOptionAction">Apply <see cref="UdapConfigurationStoreOptions"/></param>
    /// <param name="baseUrl">Supply the baseUrl or set UdapIdpBaseUrl environment variable.</param>
    /// <returns></returns>
    /// <exception cref="Exception">If missing baseUrl and UdapIdpBaseUrl environment variable.</exception>
    public static IUdapServiceBuilder AddUdapServerAsIdentityProvider(
        this IServiceCollection services,
        Action<ServerSettings>? setupAction = null,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null,
        string? baseUrl = null)
    {
        var builder = services.AddUdapServerBuilder();

        if (setupAction != null)
        {
            services.Configure(setupAction);
        }

        builder.Services.TryAddSingleton<IPostConfigureOptions<ServerSettings>, TieredIdpServerSettings>();
        builder.AddUdapSigningCredentials<UdapMetadataOptions>();
        services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<ServerSettings>>().Value);
        builder.AddRegistrationEndpointToOpenIdConnectMetadata(baseUrl);
        builder.AddUdapServerConfiguration();
        builder.AddUdapConfigurationStore<UdapDbContext>(storeOptionAction);
        builder.AddUdapJwtBearerClientAuthentication();

        return builder;
    }
}

