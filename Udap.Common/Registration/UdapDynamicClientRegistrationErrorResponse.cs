#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;

namespace Udap.Common.Registration;

public class UdapDynamicClientRegistrationErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; set; }
    
    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; }
}