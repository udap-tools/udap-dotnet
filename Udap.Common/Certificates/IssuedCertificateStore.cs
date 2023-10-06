using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.X509;
using Udap.Common.Models;

namespace Udap.Common.Certificates;

public class IssuedCertificateStore : IPrivateCertificateStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private readonly ILogger<IssuedCertificateStore> _logger;
    private string? _resourceServerName;
    private bool _resolved;


    public IssuedCertificateStore(
        IOptionsMonitor<UdapFileCertStoreManifest> manifest,
        ILogger<IssuedCertificateStore> logger,
        string? resourceServerName = null)
    {
        _manifest = manifest;
        _resourceServerName = resourceServerName;
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

        if (_resourceServerName == null)
        {
            _logger.LogInformation($"Loading first ResourceServers from UdapFileCertStoreManifest:ResourceServers.");

            communities = manifestCurrentValue.Communities;
        }
        else
        {
            _logger.LogInformation($"Loading UdapFileCertStoreManifest:ResourceServers:Name {_resourceServerName}.");

            communities = manifestCurrentValue.Communities;
        }

        _logger.LogInformation($"{communities.Count} communities loaded");

        foreach (var community in communities)
        {
            _logger.LogInformation($"Loading Community:: Name: '{community.Name}' IdPBaseUrl: '{community.IdPBaseUrl}'");

            foreach (var communityIssuer in community.IssuedCerts)
            {
                if (communityIssuer.FilePath == null)
                {
                    _logger.LogWarning($"Missing file path in on of the anchors {nameof(community.IssuedCerts)}");
                }

                if (communityIssuer.FilePath != null)
                {
                    var path = Path.Combine(AppContext.BaseDirectory, communityIssuer.FilePath);

                    if (!File.Exists(path))
                    {
                        _logger.LogWarning($"Cannot find file: {path}");
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
                            _logger.LogInformation($"Loading Certificate:: Thumbprint: {x509Cert.Thumbprint}  Subject: {x509Cert.SubjectName.Name}");
                            IssuedCertificates.Add(new IssuedCertificate
                            {
                                Community = community.Name,
                                IdPBaseUrl = community.IdPBaseUrl,
                                Certificate = x509Cert,
                                Thumbprint = x509Cert.Thumbprint
                            });
                        }
                    }
                }
            }
        }
    }

}