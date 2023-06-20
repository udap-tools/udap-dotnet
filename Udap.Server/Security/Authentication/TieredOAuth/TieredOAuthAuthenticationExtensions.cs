using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Udap.Client.Authentication;
using Udap.Client.Client;

namespace Udap.Server.Security.Authentication.TieredOAuth;
public static class TieredOAuthAuthenticationExtensions
{


    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth([NotNull] this AuthenticationBuilder builder)
    {
        return builder.AddTieredOAuth(TieredOAuthAuthenticationDefaults.AuthenticationScheme, options => { });
    }

    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configuration">The delegate used to configure the Tiered OAuth options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] Action<TieredOAuthAuthenticationOptions> configuration)
    {
        return builder.AddTieredOAuth(TieredOAuthAuthenticationDefaults.AuthenticationScheme, configuration);
    }

    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Tiered OAuth options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] string scheme,
        [NotNull] Action<TieredOAuthAuthenticationOptions> configuration)
    {
        return builder.AddTieredOAuth(scheme, TieredOAuthAuthenticationDefaults.DisplayName, configuration);
    }

    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="caption">The optional display name associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Tiered OAuth options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth(
        this AuthenticationBuilder builder, 
        string scheme,
        string caption,
        Action<TieredOAuthAuthenticationOptions> configuration)
    {
        builder.Services.TryAddSingleton<UdapClientMessageHandler>();
        builder.Services.TryAddSingleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>();
        return builder.AddOAuth<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>(scheme, caption, configuration);
    }
}

public class TieredOAuthPostConfigureOptions : IPostConfigureOptions<TieredOAuthAuthenticationOptions>

{
    private readonly UdapClientMessageHandler _udapClientMessageHandler;

    /// <summary>
    /// Initializes a new instance of the <see cref="TieredOAuthPostConfigureOptions"/> class.
    /// </summary>
    /// <param name="udapClientMessageHandler"></param>
    public TieredOAuthPostConfigureOptions(UdapClientMessageHandler udapClientMessageHandler)
    {
        _udapClientMessageHandler = udapClientMessageHandler;
    }

    /// <summary>
    /// Invoked to configure a <typeparamref name="TieredOAuthAuthenticationOptions" /> instance.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The options instance to configured.</param>
    public void PostConfigure(string? name, TieredOAuthAuthenticationOptions options)
    {
        options.BackchannelHttpHandler = _udapClientMessageHandler;
    }
}
