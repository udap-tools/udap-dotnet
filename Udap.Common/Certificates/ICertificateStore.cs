#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;

namespace Udap.Common.Certificates;

public interface ICertificateStore
{
    ICollection<X509Certificate2> AnchorCertificates { get; set; }

    ICollection<Anchor> IntermediateCertificates { get; set; }

    ICollection<IssuedCertificate> IssuedCertificates { get; set; }

    Task<ICertificateStore> Resolve();
}