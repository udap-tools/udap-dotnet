#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Extensions;

namespace Udap.Common.Models;

public class Anchor : IEquatable<Anchor>
{
    public Anchor(){}
    public Anchor(X509Certificate2 cert, string? name = null)
    {
        Certificate = cert.ToPemFormat();
        BeginDate = cert.NotBefore;
        EndDate = cert.NotAfter;
        Thumbprint = cert.Thumbprint;
        Name = name ?? cert.Subject;
    }
    public long Id { get; set; }
    public bool Enabled { get; set; }
    public string Name { get; set; }
    public string Community { get; set; }
    public long CommunityId { get; set; }
    public string Certificate { get; set; }
    public string Thumbprint { get; set; }
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }


    /// <summary>Returns a string that represents the current object.</summary>
    /// <returns>A string that represents the current object.</returns>
    public override string ToString()
    {
        return $"Thumbprint {Thumbprint} | Name {Name}";
    }

    /// <summary>Serves as the default hash function.</summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode()
    {
        return ToString().GetHashCode();
    }

    /// <summary>Indicates whether the current object is equal to another object of the same type.</summary>
    /// <param name="other">An object to compare with this object.</param>
    /// <returns>
    /// <see langword="true" /> if the current object is equal to the <paramref name="other" /> parameter; otherwise, <see langword="false" />.</returns>
    public bool Equals(Anchor? other)
    {
        if (other == null) return false;
        return other.Thumbprint == this.Thumbprint;
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