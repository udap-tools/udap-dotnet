#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;

namespace Udap.Common.Models;

public class IssuedCertificate : IEquatable<IssuedCertificate>
{
    public IssuedCertificate(){} // do not remove
    public IssuedCertificate(X509Certificate2 certificate, string community = "")
    {
        Certificate = certificate;
        Community = community;
        Thumbprint = certificate.Thumbprint;
    }

    public string Community { get; }

    public X509Certificate2 Certificate { get; }
    
    public string Thumbprint { get; }

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
    public bool Equals(IssuedCertificate? other)
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
        if (obj is IssuedCertificate issued) return Equals(issued);
        return false;
    }
}