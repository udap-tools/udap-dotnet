#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.CA.Services;

public enum CertSecurityLevel : byte
{
    Software = 0,
    Fips1403 = 1
}