#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;

namespace Udap.Model
{
    /// <summary>
    /// Configurable data typically loaded from AppSettings.
    /// </summary>
    public class UdapConfig
    {
        public bool Enabled { get; set; }

        public List<UdapMetadataConfig> UdapMetadataConfigs { get; set; } = new();
    }
}
