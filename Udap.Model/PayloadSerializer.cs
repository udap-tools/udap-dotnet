﻿#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Udap.Model.Registration;
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
    /// <typeparam name="T"></typeparam>
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
                deserializedValue = Deserialize<B2BAuthorizationExtension>(item.Value.GetRawText());
            }
            else if (item.Name == UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER)
            {
                deserializedValue = Deserialize<B2BUserAuthorizationExtension>(item.Value.GetRawText());
            }
            // else if (item.Name == UdapConstants.UdapAuthorizationExtensions.TEFCAIAS)
            // {
            //
            // }
            // else if (item.Name == UdapConstants.UdapAuthorizationExtensions.TEFCASMART)
            // {
            //
            // }

            else
            {
                // Default deserialization for other types
                deserializedValue = JsonSerializer.Deserialize<object>(item.Value.GetRawText());
            }

            claimValues.Add(item.Name, deserializedValue);
        }

        return claimValues;
    }

    /// <summary>
    /// Deserializer that understands the type of <see cref="JsonConverter"/> and uses the appropriate converter.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="rawJson"></param>
    /// <returns></returns>
    public static T? Deserialize<T>(string rawJson)
    {
        if (typeof(T) == typeof(UdapDynamicClientRegistrationDocument))
        {
            return JsonSerializer.Deserialize<T>(rawJson,
                new JsonSerializerOptions()
                {
                    Converters =
                    {
                        new B2BAuthorizationExtensionConverter(),
                        new B2BUserAuthorizationExtensionConverter()
                    }
                });
        }
        if (typeof(T) == typeof(B2BAuthorizationExtension))
        {
            return JsonSerializer.Deserialize<T>(rawJson,
            new JsonSerializerOptions()
            {
                Converters = { new B2BAuthorizationExtensionConverter() }
            });
        }
        else if (typeof(T) == typeof(B2BUserAuthorizationExtension))
        {
            return JsonSerializer.Deserialize<T>(rawJson,
            new JsonSerializerOptions()
            {
                Converters = { new B2BUserAuthorizationExtensionConverter() }
            });
        }

        return default;
    }
}
