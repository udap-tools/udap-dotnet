using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common.Models;

namespace Udap.Common.Certificates;

public class IssuedCertificateStore : IPrivateCertificateStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private readonly ILogger<IssuedCertificateStore> _logger;
    private bool _resolved;


    public IssuedCertificateStore(
        IOptionsMonitor<UdapFileCertStoreManifest> manifest,
        ILogger<IssuedCertificateStore> logger)
    {
        _manifest = manifest;
        _logger = logger;

        _manifest.OnChange(_ =>
        {
            _resolved = false;
        });
    }

    public Task<IPrivateCertificateStore> Resolve()
    {
        if (_resolved == false)
        {
            LoadCertificates(_manifest.CurrentValue);
        }
        _resolved = true;

        return Task.FromResult(this as IPrivateCertificateStore);
    }

    public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new HashSet<IssuedCertificate>();

    // TODO convert to Lazy<T> to protect from race conditions

    private void LoadCertificates(UdapFileCertStoreManifest manifestCurrentValue)
    {
        ICollection<Common.Metadata.Community>? communities;
        communities = manifestCurrentValue.Communities;
        _logger.LogInformation("{Count} communities loaded", communities.Count);

        foreach (var community in communities)
        {
            _logger.LogInformation("Loading Community:: Name: '{CommunityName}'", community.Name);

            foreach (var communityIssuer in community.IssuedCerts)
            {
                if (communityIssuer.FilePath == null)
                {
                    _logger.LogWarning("Missing file path in one of the anchors {IssuedCerts}", nameof(community.IssuedCerts));
                }

                if (communityIssuer.FilePath != null)
                {
                    var path = Path.Combine(AppContext.BaseDirectory, communityIssuer.FilePath);

                    if (!File.Exists(path))
                    {
                        _logger.LogWarning("Cannot find file: {FilePath}", path);
                        continue;
                    }

                    var certificates = new X509Certificate2Collection();
                    certificates.Import(path, communityIssuer.Password, X509KeyStorageFlags.Exportable);

                    foreach (var x509Cert in certificates)
                    {
                        if (x509Cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.19") 
                                is X509BasicConstraintsExtension extension && 
                            !extension.CertificateAuthority)
                        {
                            _logger.LogInformation("Loading Certificate:: Thumbprint: {Thumbprint}  Subject: {SubjectName}", x509Cert.Thumbprint, x509Cert.SubjectName.Name);
                            IssuedCertificates.Add(new IssuedCertificate(x509Cert, community.Name));
                        }
                    }
                }
            }
        }
    }

}