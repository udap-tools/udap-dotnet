#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Model;

public class UdapMetadataConfig
{

    /// <summary>
    /// See <a href="http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities">Multiple Trust Communities</a>
    /// </summary>
    public string Community { get; set; } = string.Empty;


    /// <summary>
    /// See <a href="http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements">Signed metadata elements</a>
    /// Signed Metadata JWT claims
    /// </summary>
    public SignedMetadataConfig SignedMetadataConfig { get; set; } = new();
}