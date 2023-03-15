#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;

namespace Udap.Model.Registration;
public class UdapRegisterRequest
{
    public UdapRegisterRequest(){}

    /// <summary>Initializes a new instance of the <see cref="T:System.Object"></see> class.</summary>
    public UdapRegisterRequest(string softwareStatement, string udap)
    {
        SoftwareStatement = softwareStatement;
        Udap = udap;
    }

    public UdapRegisterRequest(string softwareStatement, string udap, string[] certifications)
    {
        SoftwareStatement = softwareStatement;
        Udap = udap;
        Certifications = certifications;
    }

    /// <summary>
    /// JWS compact serialization
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationRequestBody.SoftwareStatement)]
    public string SoftwareStatement { get; set; } = default!;

    /// <summary>
    /// List of JWS compact serialization
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Certifications)]
    public string[]? Certifications { get; set; }

    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Udap)]
    public string Udap { get; set; } = default!;
}
