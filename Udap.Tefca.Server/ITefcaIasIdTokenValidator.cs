#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Server.Validation;

namespace Udap.Tefca.Server;

/// <summary>
/// Validates the <c>id_token</c> carried in a <c>tefca_ias</c> authorization extension object.
/// <para>
/// <c>AddUdapTefcaValidation</c> registers <see cref="DefaultTefcaIasIdTokenValidator"/>, which accepts only issuers
/// listed in <see cref="TefcaValidationOptions.TrustedIasIssuers"/> and checks signature, lifetime and, when
/// configured, audience. Register your own implementation instead to apply other rules, for example binding the token
/// to the request:
/// </para>
/// <code>
/// builder.Services.AddSingleton&lt;ITefcaIasIdTokenValidator, MyIasIdTokenValidator&gt;();
/// builder.Services.AddUdapTefcaValidation();
/// </code>
/// </summary>
public interface ITefcaIasIdTokenValidator
{
    /// <summary>
    /// Validates <paramref name="idToken"/>. Return <see cref="AuthorizationExtensionValidationResult.Success"/> to
    /// accept it, or a failure (typically <c>invalid_grant</c>) to reject the token request.
    /// </summary>
    /// <param name="idToken">The <c>id_token</c> value from the <c>tefca_ias</c> extension; never empty.</param>
    /// <param name="context">The token request being validated: client, registered SAN, grant type and extensions.</param>
    Task<AuthorizationExtensionValidationResult> ValidateAsync(
        string idToken,
        UdapAuthorizationExtensionValidationContext context);
}
