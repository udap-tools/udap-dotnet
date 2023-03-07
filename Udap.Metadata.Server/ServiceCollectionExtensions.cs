#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Metadata.Server;
using Udap.Model;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    // TODO this is not flexible to work with implementations that do not use UdapConfig in appsettings.

    public static IMvcBuilder AddUdapMetaDataServer(
        this IMvcBuilder mvcBuilder,
        ConfigurationManager configuration)
    {
        var services = mvcBuilder.Services;
        services.Configure<UdapConfig>(configuration.GetSection("UdapConfig"));
        mvcBuilder.Services.TryAddSingleton<UdapMetadata>();

        var assembly = typeof(UdapController).Assembly;
        return mvcBuilder.AddApplicationPart(assembly);
    }
}

