using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common.Models;

namespace Udap.Common.Certificates;

/// <summary>
/// File-based implementation of <see cref="IPrivateCertificateStore"/> that loads issued
/// end-entity certificates from PFX files specified in the <see cref="UdapFileCertStoreManifest"/>.
/// Supports hot-reload via <see cref="IOptionsMonitor{T}"/> and thread-safe resolution.
/// </summary>
public class IssuedCertificateStore : IPrivateCertificateStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private readonly ILogger<IssuedCertificateStore> _logger;
    private bool _resolved;
    private readonly SemaphoreSlim _resolveSemaphore = new SemaphoreSlim(1, 1);

    /// <summary>
    /// Initializes a new instance of the <see cref="IssuedCertificateStore"/>.
    /// </summary>
    /// <param name="manifest">The monitored certificate store manifest configuration.</param>
    /// <param name="logger">The logger instance.</param>
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

    /// <inheritdoc />
    public async Task<IPrivateCertificateStore> Resolve(CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();

        await _resolveSemaphore.WaitAsync(token);
        try
        {
            if (_resolved == false)
            {
                await Task.Run(() => LoadCertificates(_manifest.CurrentValue), token);
            }
        }
        finally
        {
            _resolveSemaphore.Release();
        }
        _resolved = true;

        return this;
    }

    /// <inheritdoc />
    public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new HashSet<IssuedCertificate>();

    private void LoadCertificates(UdapFileCertStoreManifest manifestCurrentValue)
    {
        ICollection<Metadata.Community> communities = manifestCurrentValue.Communities;
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

#if NET9_0_OR_GREATER
                    var certificates = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, communityIssuer.Password, X509KeyStorageFlags.Exportable);
#else
                    var certificates = new X509Certificate2Collection();
                    certificates.Import(path, communityIssuer.Password, X509KeyStorageFlags.Exportable);
#endif

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
