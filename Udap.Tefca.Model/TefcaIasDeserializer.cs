#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Tefca.Model;

/// <summary>
/// Deserializer for the TEFCA IAS authorization extension ("tefca_ias").
/// Register via DI to enable PayloadSerializer to handle this extension type.
/// </summary>
public class TefcaIasDeserializer : IAuthorizationExtensionDeserializer
{
    /// <inheritdoc />
    public string ExtensionKey => TefcaConstants.UdapAuthorizationExtensions.TEFCAIAS;

    /// <inheritdoc />
    public object? Deserialize(string json)
    {
        return JsonSerializer.Deserialize<TEFCAIASAuthorizationExtension>(json);
    }
}
