#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Entitiies;

public class Community
{
    public long Id { get; set; }

    public string Name { get; set; }

    public bool Enabled { get; set; }

    public bool Default { get; set; }

    /// <summary>
    /// Generally a community has one Anchor.
    /// But during rollover from an expired anchor to a new anchor
    /// there could be two for a short time.
    /// </summary>
    public ICollection<Anchor>? Anchors { get; set; }

    /// <summary>
    /// A community may have named certifications.  This is a list of possible
    /// certifications.
    /// </summary>
    public ICollection<Certification>? Certifications { get; set; }

    public virtual ICollection<CommunityCertification> CommunityCertifications { get; set; }
}