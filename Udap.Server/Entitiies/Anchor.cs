#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Entitiies;

public class Anchor
{
    public long Id { get; set; }

    public bool Enabled { get; set; }
    public string Name { get; set; }
    /// <summary>
    /// Base64 Der encoded
    /// </summary>
    public string X509Certificate { get; set; }
    public string Thumbprint { get; set; }
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public Community Community { get; set; }
    public long CommunityId { get; set; }

    public virtual ICollection<AnchorCertification> AnchorCertifications { get; set; }
}

public class UdapRootCAs
{
    public long Id { get; set; }

    public bool Enabled { get; set; }
    public string Name { get; set; }
    /// <summary>
    /// Base64 Der encoded
    /// </summary>
    public string X509Certificate { get; set; }
    public string Thumbprint { get; set; }
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public List<Community> Communities { get; set; }
}