#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;
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
}
