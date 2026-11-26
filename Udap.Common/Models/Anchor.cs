#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Util.Extensions;

namespace Udap.Common.Models;

/// <summary>
/// Represents a trust anchor (root CA) certificate in the UDAP trust framework.
/// Anchors define the roots of trust for certificate chain validation within a community.
/// </summary>
public class Anchor: IEquatable<Anchor>
{
    /// <summary>
    /// Initializes a new empty instance. Required for serialization and EF Core materialization.
    /// </summary>
    public Anchor() { }

    /// <summary>
    /// Initializes a new instance from an X.509 certificate.
    /// </summary>
    /// <param name="cert">The X.509 certificate to use as a trust anchor.</param>
    /// <param name="communityName">The UDAP community this anchor belongs to.</param>
    /// <param name="name">A display name for the anchor. Defaults to the certificate subject.</param>
    /// <remarks>An anchor built from a certificate is enabled. Set <see cref="Enabled"/> to false to keep it but not trust it.</remarks>
    public Anchor(X509Certificate2 cert, string? communityName = null, string? name = null)
    {
        Enabled = true;
        Certificate = cert.ToPemFormat();
        BeginDate = cert.NotBefore;
        EndDate = cert.NotAfter;
        Thumbprint = cert.Thumbprint;
        Community = communityName;
        Name = name ?? cert.Subject;
    }

    /// <summary>Gets or sets the database identifier.</summary>
    public long Id { get; set; }

    /// <summary>
    /// Gets or sets whether this anchor is trusted. Stores return only enabled anchors in enabled communities.
    /// The certificate constructor sets it to true; the parameterless constructor (used for serialization and
    /// storage) leaves it false until set.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the display name, typically the certificate subject.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the UDAP community name (URI) this anchor belongs to.</summary>
    public string? Community { get; set; }

    /// <summary>Gets or sets the foreign key to the <see cref="Models.Community"/>.</summary>
    public long CommunityId { get; set; }

    /// <summary>Gets or sets the PEM-encoded certificate data.</summary>
    public string Certificate { get; set; } = string.Empty;

    /// <summary>Gets or sets the SHA-1 thumbprint of the certificate.</summary>
    public string Thumbprint { get; set; } = string.Empty;

    /// <summary>Gets or sets the certificate's NotBefore date.</summary>
    public DateTime BeginDate { get; set; }

    /// <summary>Gets or sets the certificate's NotAfter date.</summary>
    public DateTime EndDate { get; set; }

    /// <summary>Gets or sets the intermediate certificates chained to this anchor.</summary>
    public virtual ICollection<Intermediate>? Intermediates { get; set; } = default!;

    /// <summary>Returns a string that represents the current object.</summary>
    /// <returns>A string that represents the current object.</returns>
    public override string ToString()
    {
        return $"Thumbprint {Thumbprint} | Name {Name} | Community {Community}";
    }

    /// <summary>Serves as the default hash function.</summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(Thumbprint, Community);
    }

    /// <summary>Indicates whether the current object is equal to another object of the same type.</summary>
    /// <param name="other">An object to compare with this object.</param>
    /// <returns>
    /// <see langword="true" /> if the current object is equal to the <paramref name="other" /> parameter; otherwise, <see langword="false" />.</returns>
    public bool Equals(Anchor? other)
    {
        if (other == null) return false;
        return other.Thumbprint == this.Thumbprint && 
               other.Community == this.Community;
    }

    /// <summary>Determines whether the specified object is equal to the current object.</summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns>
    /// <see langword="true" /> if the specified object  is equal to the current object; otherwise, <see langword="false" />.</returns>
    public override bool Equals(object? obj)
    {
        if (obj is Anchor anchor) return Equals(anchor);
        return false;
    }
}