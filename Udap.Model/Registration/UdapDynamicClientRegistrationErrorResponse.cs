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

public class UdapDynamicClientRegistrationErrorResponse
{
    /// <summary>Initializes a new instance of the <see cref="T:System.Object"></see> class.</summary>
    public UdapDynamicClientRegistrationErrorResponse(string error, string errorDescription)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    [JsonPropertyName("error")]
    public string Error { get; set; }
    
    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; }
}