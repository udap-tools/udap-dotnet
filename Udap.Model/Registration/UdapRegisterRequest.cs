#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Text.Json.Serialization;

namespace Udap.Model.Registration;
public class UdapRegisterRequest
{
    /// <summary>
    /// JWS compact serialization
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationRequestBody.SoftwareStatement)]
    public string SoftwareStatement { get; set; }

    /// <summary>
    /// List of JWS compact serialization
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Certifications)]
    public string[]? Certifications { get; set; } = Array.Empty<string>();

    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Udap)]
    public string Udap { get; set; }
}
