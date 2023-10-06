#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using Udap.Common.Metadata;

namespace Udap.Common;

public class UdapFileCertStoreManifest
{
    public ICollection<Community> Communities { get; set; } = new List<Community>();
}