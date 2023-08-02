#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Models;

public class Community
{
    public int Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public bool Enabled { get; set; }

    public bool Default { get; set; }

    public ICollection<Anchor>? Anchors { get; set; }

    public ICollection<Certification>? Certifications { get; set; }
}