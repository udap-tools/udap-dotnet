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

public class IssuedCertificate 
{
    public int Id { get; set; }
    public bool Enabled { get; set; }
    // public string Name { get; set; } = string.Empty;
    public string? IdPBaseUrl { get; set; }
    public string Community { get; set; } = string.Empty;

    public X509Certificate2 Certificate { get; set; } = default!;
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public string Thumbprint { get; set; }

    /// <summary>Serves as the default hash function.</summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode()
    {
        return Thumbprint.GetHashCode();
    }

    /// <summary>Determines whether the specified object is equal to the current object.</summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns>
    /// <see langword="true" /> if the specified object  is equal to the current object; otherwise, <see langword="false" />.</returns>
    public override bool Equals(object? obj)
    {
        return obj is IssuedCertificate issued && issued.Thumbprint.Equals(Thumbprint) && issued.Community.Equals(Community);
    }
}