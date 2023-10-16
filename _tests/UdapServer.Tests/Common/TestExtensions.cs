#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Model;
using Udap.Server.Hosting.DynamicProviders.Oidc;
using Udap.Server.Security.Authentication.TieredOAuth;

namespace UdapServer.Tests.Common;
public static class TestExtensions
{
    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configuration">The delegate used to configure the Tiered OAuth options.</param>
    /// <param name="handler">Inject delegating handler attached to HttpClient</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuthForTests(
        this AuthenticationBuilder builder,
        Action<TieredOAuthAuthenticationOptions> configuration,
        UdapIdentityServerPipeline pipelineIdp1,
        UdapIdentityServerPipeline pipelineIdp2)
    {
        builder.Services.AddScoped<IUdapClient>(sp =>
        {
            var dynamicIdp = sp.GetRequiredService<DynamicIdp>();

            if (dynamicIdp.Name == "https://idpserver")
            {
                return new UdapClient(
                    pipelineIdp1.BackChannelClient,
                    sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                    sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                    sp.GetRequiredService<ILogger<UdapClient>>());
            }

            if (dynamicIdp?.Name == "https://idpserver2")
            {
                return new UdapClient(
                    pipelineIdp2.BackChannelClient,
                    sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                    sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                    sp.GetRequiredService<ILogger<UdapClient>>());
            }

            return null;
        });

        builder.Services.TryAddSingleton<UdapClientDiscoveryValidator>();
        builder.Services.TryAddSingleton<UdapClientMessageHandler>();
        builder.Services.TryAddSingleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>();
        return builder.AddOAuth<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>(
            TieredOAuthAuthenticationDefaults.AuthenticationScheme,
            TieredOAuthAuthenticationDefaults.DisplayName, 
            configuration);
    }

    public static IServiceCollection AddTieredOAuthDynamicProviderForTests(
        this IServiceCollection services,
        UdapIdentityServerPipeline pipelineIdp1,
        UdapIdentityServerPipeline pipelineIdp2)
    {
        services.Configure<IdentityServerOptions>(options =>
        {
            // this associates the TieredOAuthAuthenticationHandler and options (TieredOAuthAuthenticationOptions) classes
            // to the idp class (OidcProvider) and type value ("udap_oidc") from the identity provider store
            options.DynamicProviders.AddProviderType<TieredOAuthAuthenticationHandler, TieredOAuthAuthenticationOptions, OidcProvider>("udap_oidc");
        });






        // this registers the OidcConfigureOptions to build the TieredOAuthAuthenticationOptions from the OidcProvider data
        services.AddSingleton<IConfigureOptions<TieredOAuthAuthenticationOptions>, UdapOidcConfigureOptions>();


        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>());

        services.TryAddTransient<TieredOAuthAuthenticationHandler>();

        
        
        services.TryAddSingleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>();

        
        
        
        
        
        
        services.AddScoped<IUdapClient>(sp =>
        {
            var dynamicIdp = sp.GetRequiredService<DynamicIdp>();

            if (dynamicIdp.Name == "https://idpserver")
            {
                return new UdapClient(
                    pipelineIdp1.BackChannelClient,
                    sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                    sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                    sp.GetRequiredService<ILogger<UdapClient>>());
            }

            if (dynamicIdp?.Name == "https://idpserver2")
            {
                return new UdapClient(
                    pipelineIdp2.BackChannelClient,
                    sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                    sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                    sp.GetRequiredService<ILogger<UdapClient>>());
            }

            return null;
        });

        services.TryAddSingleton<UdapClientDiscoveryValidator>();
        services.TryAddSingleton<UdapClientMessageHandler>();

        return services;
    }
}
