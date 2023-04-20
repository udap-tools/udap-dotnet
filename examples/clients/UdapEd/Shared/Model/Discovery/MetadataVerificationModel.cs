#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Model;

namespace UdapEd.Shared.Model.Discovery;

public class MetadataVerificationModel
{
    public UdapMetadata? UdapServerMetaData { get; set; }

    public List<string> Notifications { get; set; } = new List<string>();
}
