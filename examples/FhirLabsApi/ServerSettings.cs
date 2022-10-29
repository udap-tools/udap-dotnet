#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace FhirLabsApi
{
    public class ServerSettings
    {
        public string[]? AllowedOrigins { get; set; }
        public string? ServerBaseDirectory { get; set; }
    }

    public static class ConfigurationExtension
    {
        public static TOptions GetOption<TOptions>(this IConfiguration configuration, string settingKey)
            where TOptions : class, new()
        {
            var options = new TOptions();
            configuration.Bind(settingKey, options);
            return options;
        }
    }
}
