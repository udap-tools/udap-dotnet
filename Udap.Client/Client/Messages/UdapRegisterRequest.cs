#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;
using Udap.Model;

namespace Udap.Client.Client.Messages;
public class UdapRegisterRequest
{
    [JsonPropertyName(UdapConstants.RegistrationRequestBody.SoftwareStatement)]
    public string SoftwareStatement { get; set; }

    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Certifications)]
    public string[] Certifications { get; set; }

    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Udap)]
    public string Udap { get; set; }
}
