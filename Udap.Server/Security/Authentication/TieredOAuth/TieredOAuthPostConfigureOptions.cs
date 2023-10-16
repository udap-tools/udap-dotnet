#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using System.Reflection.Metadata;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredOAuthPostConfigureOptions : IPostConfigureOptions<TieredOAuthAuthenticationOptions>

{
    private readonly UdapClientMessageHandler _udapClientMessageHandler;
    private readonly IDataProtectionProvider _dataProtection;

    /// <summary>
    /// Initializes a new instance of the <see cref="TieredOAuthPostConfigureOptions"/> class.
    /// </summary>
    /// <param name="udapClientMessageHandler"></param>
    public TieredOAuthPostConfigureOptions(UdapClientMessageHandler udapClientMessageHandler, IDataProtectionProvider dataProtection)
    {
        _udapClientMessageHandler = udapClientMessageHandler;
        _dataProtection = dataProtection;
    }

    /// <summary>
    /// Invoked to configure a <typeparamref name="TieredOAuthAuthenticationOptions" /> instance.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The options instance to configured.</param>
    public void PostConfigure(string? name, TieredOAuthAuthenticationOptions options)
    {
        //TODO Register _udapClientMessageHandler events for logging

        options.BackchannelHttpHandler = _udapClientMessageHandler;
        options.SignInScheme = options.SignInScheme;
        options.DataProtectionProvider ??= _dataProtection;



        if (options.StateDataFormat == null)
        {
            var dataProtector = options.DataProtectionProvider.CreateProtector(
                typeof(TieredOAuthAuthenticationHandler).FullName!, name, "v1");
            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }



        //
        // If I go down the path of OpendIdConnectHandler remember to visit the OpenIdConnectPostConfigureOptions source for guidance
        //
        // if (options.StateDataFormat == null)
        // {
        //     var dataProtector = options.DataProtectionProvider.CreateProtector(
        //         typeof(OpenIdConnectHandler).FullName!, name, "v1");
        //     options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        // }
        //
        // if (options.StringDataFormat == null)
        // {
        //     var dataProtector = options.DataProtectionProvider.CreateProtector(
        //         typeof(OpenIdConnectHandler).FullName!,
        //         typeof(string).FullName!,
        //         name,
        //         "v1");
        //
        //     options.StringDataFormat = new SecureDataFormat<string>(new StringSerializer(), dataProtector);
        // }
    }
}