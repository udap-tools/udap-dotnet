#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Hosting;
using Duende.IdentityServer.ResponseHandling;
using IdentityModel;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Server;
using Udap.Server.Configuration.DependencyInjection;
using Udap.Server.DbContexts;
using Udap.Server.Options;
using Udap.Server.ResponseHandling;
using Udap.Server.Stores;
using Udap.Server.Validation;
using Constants = Udap.Server.Constants;

#pragma warning disable IDE0130 // Namespace does not match folder structure
// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static  class UdapServiceBuilderExtensionsCore
{
    public static IUdapServiceBuilder AddRegistrationEndpointToOpenIdConnectMetadata(
        this IUdapServiceBuilder builder,
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

        baseUrl = $"{baseUrl.EnsureTrailingSlash()}{Constants.ProtocolRoutePaths.Register}";

        builder.Services.Configure<IdentityServerOptions>(options =>
            options.Discovery.CustomEntries.Add(
                OidcConstants.Discovery.RegistrationEndpoint,
                baseUrl));

        return builder;
    }

    public static IUdapServiceBuilder AddUdapDiscovery(
        this IUdapServiceBuilder builder)
    {
        builder.Services.AddTransient<UdapDiscoveryEndpoint>();
        builder.Services.AddSingleton(new Endpoint(
            Constants.EndpointNames.Discovery, 
            Constants.ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash(), 
            typeof(UdapDiscoveryEndpoint)));
        
        return builder;
    }

    public static IUdapServiceBuilder AddUdapConfigurationStore(
        this IUdapServiceBuilder builder,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
    {
        return builder.AddUdapConfigurationStore<UdapDbContext>(storeOptionAction);
    }

    public static IUdapServiceBuilder AddUdapConfigurationStore<TContext>(
        this IUdapServiceBuilder builder,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
        where TContext : DbContext, IUdapDbAdminContext, IUdapDbContext
    {
        builder.Services.AddUdapDbContext<TContext>(storeOptionAction);
        builder.AddUdapClientRegistrationStore<UdapClientRegistrationStore>();

        return builder;
    }

    public static IUdapServiceBuilder AddSmartV2Expander(this IUdapServiceBuilder builder)
    {
        builder.Services.AddScoped<IScopeExpander, HL7SmartScopeExpander>();
        
        return builder;
    }

    public static IUdapServiceBuilder AddUdapResponseGenerators(this IUdapServiceBuilder builder)
    {
        // Replace pluggable service with generator that will augment the IdToken with the hl7_identifier 
        builder.Services.TryAddTransient<ITokenResponseGenerator, UdapTokenResponseGenerator>();

        return builder;
    }

    public static IUdapServiceBuilder AddPrivateFileStore(this IUdapServiceBuilder builder, string? resourceServerName = null)
    {
        builder.Services.TryAddSingleton<IPrivateCertificateStore>(sp =>
            new IssuedCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                sp.GetRequiredService<ILogger<IssuedCertificateStore>>()));

        return builder;
    }
}