#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;

namespace Udap.CA.Entities;

public class IssuedCertificate
{
    public int Id { get; set; }
    public int AnchorId { get; set; }
    public bool Enabled { get; set; }
    public string Name { get; set; }
    public string Community { get; set; }

    public string Certificate { get; set; }
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public Anchor Anchor { get; set; }
}