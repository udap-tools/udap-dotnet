#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Server.Storage.Entities;

namespace Udap.Server.Storage.Mappers;

public static class IntermediateCertificateMapper
{
    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static Udap.Common.Models.Intermediate ToModel(this Intermediate entity)
    {
        var certBase64 = entity.X509Certificate
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Trim();

#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64));
#else
        var cert = new X509Certificate2(Convert.FromBase64String(certBase64));
#endif

        return new Udap.Common.Models.Intermediate(
            cert,
            entity.Name)
        {
            Id = entity.Id,
            AnchorId = entity.AnchorId,
            Enabled = entity.Enabled,
            Certificate = entity.X509Certificate
        };
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static Intermediate ToEntity(this Udap.Common.Models.Intermediate model)
    {
        return new Intermediate
        {
            Id = (int)model.Id,
            AnchorId = (int)model.AnchorId,
            Enabled = model.Enabled,
            Name = model.Name,
            X509Certificate = model.Certificate,
            Thumbprint = model.Thumbprint,
            BeginDate = model.BeginDate,
            EndDate = model.EndDate
        };
    }
}
