using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Client.Client;
using Udap.Server.Security.Authentication.TieredOAuth;
using System.Net.Http;
using Udap.Common.Certificates;
using Microsoft.Extensions.Logging;
using Udap.Client.Configuration;

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
        UdapIdentityServerPipeline pipeline)
    {
        builder.Services.AddScoped<IUdapClient>(sp =>
            new UdapClient(
                pipeline.BrowserClient,
                sp.GetRequiredService<TrustChainValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>(),
                sp.GetRequiredService<ITrustAnchorStore>()));
        
            
        builder.Services.TryAddSingleton<UdapClientMessageHandler>();
        builder.Services.TryAddSingleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>();
        return builder.AddOAuth<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>(
            TieredOAuthAuthenticationDefaults.AuthenticationScheme,
            TieredOAuthAuthenticationDefaults.DisplayName, 
            configuration);
    }
}
