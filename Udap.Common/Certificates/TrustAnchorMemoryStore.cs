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

public class TrustAnchorMemoryStore : ITrustAnchorStore
{
    public ICollection<Anchor> AnchorCertificates { get; set; } = new HashSet<Anchor>();

    public Task<ITrustAnchorStore> Resolve()
    {
        return Task.FromResult(this as ITrustAnchorStore);
    }
}