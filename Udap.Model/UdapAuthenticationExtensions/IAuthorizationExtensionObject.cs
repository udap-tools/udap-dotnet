#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;

namespace Udap.Model.UdapAuthenticationExtensions;

/// <summary>
/// Common interface for authorization extension objects (e.g., hl7-b2b, tefca_ias).
/// Implementations provide self-validation and optional purpose_of_use extraction.
/// </summary>
public interface IAuthorizationExtensionObject
{
    /// <summary>
    /// Validates the extension object and returns a list of error messages.
    /// An empty list indicates the object is valid.
    /// </summary>
    List<string> Validate();

    /// <summary>
    /// Returns the purpose_of_use codes from this extension, if applicable.
    /// Returns null if this extension type does not carry purpose_of_use.
    /// </summary>
    ICollection<string>? GetPurposeOfUse();
}
