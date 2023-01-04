#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Entities;

public class Certification
{
    public int Id { get; set; }
    
    public string Name { get; set; }

    public virtual ICollection<CommunityCertification> CommunityCertifications { get; set; }

    public virtual ICollection<AnchorCertification> AnchorCertifications { get; set; }
}