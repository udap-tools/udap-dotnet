#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;
using Udap.Util.Extensions;

namespace Udap.Common.Extensions;
public static class CertificateStoreExtensions{

    public static X509Certificate2Collection? ToX509Collection(this IEnumerable<Anchor> anchors)
    {
        return anchors
            .Select(a => X509Certificate2.CreateFromPem(a.Certificate))
            .ToArray()
            .ToX509Collection();
    }
}
