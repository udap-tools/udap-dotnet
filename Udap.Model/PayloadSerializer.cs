#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Text.Json;
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Model;

/// <summary>
/// Helper that can understand the type being deserialized and use the appropriate converters.
/// </summary>
public static class PayloadSerializer
{
    /// <summary>
    /// <see cref="JsonElement"/> must be of ValueKind of <see cref="JsonValueKind.Object"/>
    /// </summary>
    /// <param name="jsonElement"></param>
    /// <returns></returns>
    public static Dictionary<string, object> Deserialize(JsonElement jsonElement)
    {
        var claimValues = new Dictionary<string, object>();

        foreach (var item in jsonElement.EnumerateObject())
        {
            object? deserializedValue;
            if (item.Name == UdapConstants.UdapAuthorizationExtensions.Hl7B2B)
            {
                deserializedValue = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(item.Value.GetRawText());
            }
            else if (item.Name == UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER)
            {
                deserializedValue = JsonSerializer.Deserialize<HL7B2BUserAuthorizationExtension>(item.Value.GetRawText());
            }
            else if (item.Name == UdapConstants.UdapAuthorizationExtensions.TEFCAIAS)
            {
                deserializedValue = JsonSerializer.Deserialize<TEFCAIASAuthorizationExtension>(item.Value.GetRawText());
            }
            // else if (item.Name == UdapConstants.UdapAuthorizationExtensions.TEFCASMART)
            // {
            //
            // }

            else
            {
                // Default deserialization for other types
                deserializedValue = JsonSerializer.Deserialize<object>(item.Value.GetRawText());
            }

            if (deserializedValue != null)
            {
                claimValues.Add(item.Name, deserializedValue);
            }
        }

        return claimValues;
    }

   
    public static Dictionary<string, object> Deserialize(Dictionary<string, string> jsonElement)
    {
        var claimValues = new Dictionary<string, object>();

        foreach (var item in jsonElement)
        {
            object? deserializedValue;
            if (item.Key == UdapConstants.UdapAuthorizationExtensions.Hl7B2B)
            {
                deserializedValue = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(item.Value);
            }
            else if (item.Key == UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER)
            {
                deserializedValue = JsonSerializer.Deserialize<HL7B2BUserAuthorizationExtension>(item.Value);
            }
            else if (item.Key == UdapConstants.UdapAuthorizationExtensions.TEFCAIAS)
            {
                deserializedValue = JsonSerializer.Deserialize<TEFCAIASAuthorizationExtension>(item.Value);
            }
            // else if (item.Name == UdapConstants.UdapAuthorizationExtensions.TEFCASMART)
            // {
            //
            // }

            else
            {
                // Default deserialization for other types
                deserializedValue = JsonSerializer.Deserialize<object>(item.Value);
            }

            if (deserializedValue != null)
            {
                claimValues.Add(item.Key, deserializedValue);
            }
        }

        return claimValues;
    }
}
