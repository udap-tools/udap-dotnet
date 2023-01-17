#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Udap.Model;

namespace Udap.Metadata.Server
{
    public static class ServiceCollectionExtensions
    {
        public static IMvcBuilder UseUdapMetaDataServer(
            this IMvcBuilder mvcBuilder,
            ConfigurationManager configuration,
            UdapMetadata? udapMetadata = null )
        {
            var services = mvcBuilder.Services;
            services.Configure<UdapConfig>(configuration.GetSection("UdapConfig"));

            if (udapMetadata != null)
            {
                services.AddSingleton(udapMetadata);
            }
            else
            {
                mvcBuilder.Services.AddSingleton<UdapMetadata>();

            }

            var assembly = typeof(UdapController).Assembly;
            return mvcBuilder.AddApplicationPart(assembly);
        }
    }
}
