#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.CdsHooks.Model;

public static class CdsConstants
{
    public static class Discovery
    {
        /// <summary>
        /// A CDS Service provider exposes its discovery endpoint at {baseUrl}/cds-services.
        /// </summary>
        public const string DiscoveryEndpoint = "cds-services";
    }
}
