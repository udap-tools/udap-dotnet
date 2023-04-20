#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Model.Registration;

namespace UdapEd.Shared.Model;

/// <summary>
/// Semantic naming to indicate that <see cref="UdapRegisterRequest.SoftwareStatement"/>
/// is not in raw format before being signed.
/// </summary>
public class RawUdapRegisterRequest : UdapRegisterRequest
{
}
