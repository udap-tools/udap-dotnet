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
    public class UdapMetadataOptions
    {
        public HashSet<string>? UdapVersionsSupported { get; set; } = [];
        public HashSet<string>? UdapProfilesSupported { get; set; } = [];
        public HashSet<string>? UdapAuthorizationExtensionsSupported { get; set; } = [];
        public HashSet<string>? UdapAuthorizationExtensionsRequired { get; set; } = [];
        public HashSet<string>? UdapCertificationsSupported { get; set; } = [];
        public HashSet<string>? UdapCertificationsRequired { get; set; } = [];
        public HashSet<string>? GrantTypesSupported { get; set; } = [];
        public HashSet<string>? ScopesSupported { get; set; }

        public HashSet<string>? TokenEndpointAuthSigningAlgValuesSupported { get; set; } = [];
        public HashSet<string>? RegistrationEndpointJwtSigningAlgValuesSupported { get; set; } = [];

        public List<UdapMetadataConfig> UdapMetadataConfigs { get; set; } = [];

        public int CertificateResolveTimeoutSeconds { get; set; } = 10; 
    }
}
