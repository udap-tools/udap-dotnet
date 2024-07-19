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

    /// <summary>
    /// Indicate if the IdentityServer can act as a UDAP enabled IdP.
    /// </summary>
    [JsonIgnore] 
    public bool TieredIdp { get; set; } = false;

    [JsonPropertyName("LogoRequired")]
    public bool LogoRequired { get; set; } = true;

    /// <summary>
    /// By default the jti claim is required on registration requests.  And replay attacks are monitored.
    /// </summary>
    public bool RegistrationJtiRequired { get; set; } = true;

    
    public bool AlwaysIncludeUserClaimsInIdToken { get; set; }

    public bool RequireConsent { get; set; } = true;
    public bool AllowRememberConsent { get; set; } = false;
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
