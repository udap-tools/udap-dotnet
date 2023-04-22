#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;

public class CertificateStatusViewModel
{
    public CertLoadedEnum CertLoaded { get; set;} = CertLoadedEnum.Negative;

    public List<string> SubjectAltNames { get; set;} = new List<string>();

    public string DistinguishedName { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
}