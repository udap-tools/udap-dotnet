#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Models;

namespace Udap.Common.Certificates;

public interface IPrivateCertificateStore
{
    ICollection<IssuedCertificate> IssuedCertificates { get; set; }
    Task<IPrivateCertificateStore> Resolve();
}