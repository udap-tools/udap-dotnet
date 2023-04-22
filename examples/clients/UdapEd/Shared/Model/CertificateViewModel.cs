#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;
public  class CertificateViewModel
{
    /// <summary>
    /// Dissect certificate into most used properties
    /// </summary>
    public List<Dictionary<string, string>> TableDisplay { get; set; } = new List<Dictionary<string, string>>();

    /// <summary>
    /// OpenSSL or CertUtil verbose display
    /// </summary>
    public string PlatformToolDisplay { get; set; }
}
