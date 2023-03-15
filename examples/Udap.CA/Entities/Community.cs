#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.CA.Entities;

public class Community
{
    /// <summary>Initializes a new instance of the <see cref="T:System.Object" /> class.</summary>
    public Community(string name, bool enabled)
    {
        Name = name;
        Enabled = enabled;
    }

    public int Id { get; set; }

    public string Name { get; set; }

    public bool Enabled { get; set; }
    
    /// <summary>
    /// Generally a community has one root certificate.
    /// But during rollover from an expired root certificate to a new certificate
    /// there could be two for a short time.
    /// </summary>
    public ICollection<RootCertificate>? RootCertificates { get; set; } = new HashSet<RootCertificate>();

    /// <summary>
    /// A community may have named certifications.  This is a list of possible
    /// certifications.
    /// </summary>
    //TODO: future
    // public ICollection<Certification>? Certifications { get; set; }

    // public virtual ICollection<CommunityCertification> CommunityCertifications { get; set; }
    
}