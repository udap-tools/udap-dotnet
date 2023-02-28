#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;

namespace Udap.CA.ViewModel;

public class IssuedCertificate
{
    public int Id { get; set; }
    public bool Enabled { get; set; }
    public string? Name { get; set; }
    public string? Community { get; set; }

    public X509Certificate2? Certificate { get; set; }
    public DateTime? BeginDate { get; set; }
    public DateTime? EndDate { get; set; }
}