#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Certificates;
using Udap.Common.Models;

namespace Udap.Server.Stores;

public class TrustAnchorStore : ITrustAnchorStore
{

    public TrustAnchorStore(List<Anchor> anchors)
    {
        AnchorCertificates = anchors;
    }

    public ICollection<Anchor> AnchorCertificates { get; set; }

    public Task<ITrustAnchorStore> Resolve()
    {
        return Task.FromResult<ITrustAnchorStore>(this);
    }
}