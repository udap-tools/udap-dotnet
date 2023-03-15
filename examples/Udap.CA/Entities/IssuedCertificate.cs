#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.CA.Entities;

public class IssuedCertificate
{
    public int Id { get; set; }
    public int AnchorId { get; set; }
    public bool Enabled { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Community { get; set; } = string.Empty; 

    public string Certificate { get; set; } = string.Empty;
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public Anchor? Anchor { get; set; }
}