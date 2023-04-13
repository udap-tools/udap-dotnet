#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Udap.Common.Models;
using Udap.Util.Extensions;

namespace Udap.Common.Certificates;

public class FileCertificateStore : ICertificateStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private readonly ILogger<FileCertificateStore> _logger;
    private string? _resourceServerName;
    private bool _resolved;
    

    public FileCertificateStore(
        IOptionsMonitor<UdapFileCertStoreManifest> manifest,
        ILogger<FileCertificateStore> logger,
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
    public Task<ICertificateStore> Resolve()
    {
        if (_resolved == false)
        {
            LoadCertificates(_manifest.CurrentValue);
        }
        _resolved = true;

        return Task.FromResult(this as ICertificateStore);
    }

    public ICollection<X509Certificate2> AnchorCertificates { get; set; } = new HashSet<X509Certificate2>();

    public ICollection<Anchor> IntermediateCertificates { get; set; } = new HashSet<Anchor>();
    public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new HashSet<IssuedCertificate>();

    // TODO convert to Lazy<T> to protect from race conditions

    private void LoadCertificates(UdapFileCertStoreManifest manifestCurrentValue)
    {
        ICollection<Common.Metadata.Community>? communities;

        if (_resourceServerName == null)
        {
            _logger.LogInformation($"Loading first ResourceServers from UdapFileCertStoreManifest:ResourceServers.");
            
            communities = manifestCurrentValue.ResourceServers.FirstOrDefault()?.Communities;
        }
        else
        {
            _logger.LogInformation($"Loading UdapFileCertStoreManifest:ResourceServers:Name {_resourceServerName}.");

            communities = manifestCurrentValue
                .ResourceServers
                .SingleOrDefault(r => r.Name == _resourceServerName)
                ?.Communities;
        }
        
        _logger.LogInformation($"{communities?.Count ?? 0} communities loaded");

        if (communities == null) return;

        foreach (var community in communities)
        {
            if (community.RootCAFilePaths.Any())
            {
                foreach (var communityRootCaFilePath in community.RootCAFilePaths)
                {
                    AnchorCertificates.Add(new X509Certificate2(Path.Combine(AppContext.BaseDirectory, communityRootCaFilePath)));
                }
            }

            foreach (var communityAnchor in community.Anchors)
            {
                if (communityAnchor.FilePath == null)
                {
                    throw new Exception($"Missing file path in on of the anchors {nameof(community.Anchors)}");
                }

                var path = Path.Combine(AppContext.BaseDirectory, communityAnchor.FilePath);

                if (!File.Exists(path))
                {
                    throw new FileNotFoundException($"Cannot find file: {path}");
                }

                IntermediateCertificates.Add(new Anchor(new X509Certificate2(path))
                {
                    Community = community.Name,
                });
            }

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
                    certificates.Import(path, communityIssuer.Password);
                
                    foreach (var x509Cert in certificates)
                    {
                        var extension = x509Cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.19") as X509BasicConstraintsExtension;
                        var subjectIdentifier = x509Cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.14") as X509SubjectKeyIdentifierExtension;

                        //
                        // dotnet 7.0
                        //
                        // var authorityIdentifier = cert.Extensions.FirstOrDefault(e => e.Oid.Value == "2.5.29.35") as X509AuthorityKeyIdentifierExtension;
                    
                        string? authorityIdentifierValue = null;

                        Asn1Object? exValue = x509Cert.GetExtensionValue("2.5.29.35");
                        if (exValue != null)
                        {
                            var aki = AuthorityKeyIdentifier.GetInstance(exValue);
                            byte[] keyId = aki.GetKeyIdentifier();
                            authorityIdentifierValue = keyId.CreateByteStringRep();
                        }
                    

                        if (extension != null)
                        {
                            if (extension.CertificateAuthority)
                            {
                                if (authorityIdentifierValue == null || 
                                    subjectIdentifier?.SubjectKeyIdentifier == authorityIdentifierValue)
                                {
                                    _logger.LogInformation($"Found root ca in {path} certificate.  Will add the root to roots if not already explicitly loaded.");

                                    AnchorCertificates.Add(x509Cert);
                                }
                                else
                                {
                                    _logger.LogInformation($"Found intermediate ca in {path} certificate.  Will add if not already explicitly loaded.");

                                    IntermediateCertificates.Add(new Anchor(x509Cert) { Community = community.Name });
                                }
                            }
                            else
                            {
                                IssuedCertificates.Add(new IssuedCertificate
                                {
                                    Community = community.Name,
                                    Certificate = x509Cert
                                });
                            }
                        }
                    }

                    IssuedCertificates.Add(new IssuedCertificate
                    {
                        Community = community.Name,
                        Certificate = certificates.First()
                    });
                }
            }
        }
    }
}

