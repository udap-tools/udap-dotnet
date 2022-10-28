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

namespace Udap.Metadata.Server
{
    public static class ServiceCollectionExtensions
    {
        public static IMvcBuilder UseUdapMetaData(
            this IMvcBuilder mvcBuilder,
            ConfigurationManager configuration)
        {
            var services = mvcBuilder.Services;
            services.Configure<UdapConfig>(configuration.GetSection("UdapConfig"));

            var assembly = typeof(UdapController).Assembly;
            return mvcBuilder.AddApplicationPart(assembly);
        }
    }
}
