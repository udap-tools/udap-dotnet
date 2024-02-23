#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;

namespace UdapEd.Shared.Services;
public interface IDiscoveryService
{
    Task<MetadataVerificationModel?> GetMetadataVerificationModel(string metadataUrl, string? community, CancellationToken token);
    Task<CertificateStatusViewModel?> UploadAnchorCertificate(string certBytes);
    Task<CertificateStatusViewModel?> LoadUdapOrgAnchor();
    Task<CertificateStatusViewModel?> AnchorCertificateLoadStatus();
    Task<bool> SetBaseFhirUrl(string? baseFhirUrl, bool resetToken = false);
    Task<bool> SetClientHeaders(Dictionary<string, string> headers);

    Task<CertificateViewModel?> GetCertificateData(IEnumerable<string>? base64EncodedCertificate,
        CancellationToken token);

    Task<CertificateViewModel?> GetCertificateData(string? base64EncodedCertificate,
        CancellationToken token);

    Task<string> GetFhirLabsCommunityList();
}
