#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;

namespace Udap.Server.Configuration;
public class ServerSettings
{
    [JsonPropertyName("ServerSupport")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ServerSupport ServerSupport { get; set; }

    [JsonPropertyName("DefaultSystemScopes")]
    public string? DefaultSystemScopes { get; set; }

    [JsonPropertyName("DefaultUserScopes")]
    public string? DefaultUserScopes { get; set; }

    /// <summary>
    /// Require state param to exist on /connect/authorize? calls.
    /// This is off by default.  When enabled it will only
    /// respond to clients registered with secrets of type 
    /// <see>
    ///     <cref>IdentityServerConstants.SecretTypes.Udap_X509_Pem</cref>
    /// </see>
    /// . 
    /// </summary>
    [JsonPropertyName("ForceStateParamOnAuthorizationCode")]
    public bool ForceStateParamOnAuthorizationCode { get; set; } = false;

    public ICollection<IdPMapping>? IdPMappings { get; set; } 
}

public class IdPMapping
{
    public string? Scheme { get; set; }
    public string? IdpBaseUrl { get; set; }
}

public enum ServerSupport
{
    UDAP = 0,
    Hl7SecurityIG = 1
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
