#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Validation;

/// <summary>
/// Validates authorization extension objects from a UDAP client assertion JWT
/// during token endpoint authentication. Implementors can enforce community-specific
/// rules for extensions such as hl7-b2b, hl7-b2b-user, or tefca_ias.
/// </summary>
public interface IUdapAuthorizationExtensionValidator
{
    /// <summary>
    /// Validates the authorization extension objects present in the client assertion.
    /// Called after JWT signature and PKI chain validation succeeds.
    /// </summary>
    Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context);
}
