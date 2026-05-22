#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Model.UdapAuthenticationExtensions;

/// <summary>
/// Registers a custom authorization extension deserializer for use by <see cref="PayloadSerializer"/>.
/// Implementations are discovered via DI and used to deserialize extension objects
/// by their key name (e.g., "tefca-ias").
/// </summary>
public interface IAuthorizationExtensionDeserializer
{
    /// <summary>
    /// The extension key this deserializer handles (e.g., "tefca-ias").
    /// </summary>
    string ExtensionKey { get; }

    /// <summary>
    /// Deserializes the JSON string into the appropriate extension object.
    /// The returned object should implement <see cref="IAuthorizationExtensionObject"/>.
    /// </summary>
    object? Deserialize(string json);
}
