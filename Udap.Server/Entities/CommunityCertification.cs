#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Entities;

/// <summary>
/// This is an "associate" table, to map a many to many relationship 
/// </summary>
public class CommunityCertification
{
    public virtual Community Community { get; set; }
    public int CommunityId { get; set; }
    public virtual Certification Certification { get; set; }
    public int CertificationId { get; set; }
}