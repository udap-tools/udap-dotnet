#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Model.Registration;

namespace Udap.Server.Registration;

public interface IUdapDynamicClientRegistrationValidator
{
    /// <summary>
    /// Validate registration request against all rules documented here: http://hl7.org/fhir/us/udap-security/registration.html
    /// </summary>
    /// <remarks>
    /// The validator is an implementation of <a href="https://www.udap.org/udap-dynamic-client-registration-stu1.html">
    /// UDAP Dynamic Client Registration section 4, Authorization Server validates request</a>
    /// </remarks>
    /// <param name="request"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationValidationResult> ValidateAsync(
        UdapRegisterRequest request, 
        X509Certificate2Collection communityTrustAnchors,
        X509Certificate2Collection communityRoots);
}