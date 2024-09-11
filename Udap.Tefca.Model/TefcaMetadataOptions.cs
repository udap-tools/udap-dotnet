#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Model;

namespace Udap.Tefca.Model;

/// <summary>
/// TEFCA specific extended metadata options.
/// </summary>
public class TefcaMetadataOptions : UdapMetadataOptions
{
    public HashSet<string> CertificationUris { get; set; } = new HashSet<string>(){"https://udap.surescripts.com/certifications/tefca-basic-app-certification"};

    public string CertificationName { get; set; } = "TEFCA Basic App Certification";
}
