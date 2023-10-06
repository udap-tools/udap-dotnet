﻿#region (c) 2023 Joseph Shook. All rights reserved.
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

    public ICollection<Anchor> AnchorCertificates { get; set; } = new HashSet<Anchor>();


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

        if (communities == null) return;

        foreach (var community in communities)
        {
            var intermediates = new List<Intermediate>();
            if (community.Intermediates.Any())
            {
                foreach (var intermediateFilePath in community.Intermediates)
                {
                    intermediates.Add(new Intermediate(new X509Certificate2(Path.Combine(AppContext.BaseDirectory, intermediateFilePath))));
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

                AnchorCertificates.Add(new Anchor(new X509Certificate2(path))
                {
                    Community = community.Name,
                    Intermediates = intermediates
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
                    certificates.Import(path, communityIssuer.Password, X509KeyStorageFlags.Exportable);

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
                                    _logger.LogInformation($"Ignore anchor in {path} certificate.  Never add the anchor to anchors if not already explicitly loaded.");
                                }
                                else
                                {
                                    _logger.LogInformation($"Found intermediate in {path} certificate.  Will add if not already explicitly loaded.");

                                    var anchor = AnchorCertificates.SingleOrDefault(a =>
                                    {
                                        var certificate = X509Certificate2.CreateFromPem(a.Certificate);
                                        var subjectIdentifierOfAnchor =
                                            certificate.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.14") as
                                                X509SubjectKeyIdentifierExtension;

                                        if (subjectIdentifierOfAnchor?.SubjectKeyIdentifier == authorityIdentifierValue)
                                        {
                                            return true;
                                        }

                                        return false;
                                    });

                                    anchor?.Intermediates?.Add(new Intermediate(x509Cert));
                                }
                            }
                            else
                            {
                                IssuedCertificates.Add(new IssuedCertificate
                                {
                                    Community = community.Name,
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

}
