﻿﻿#region (c) 2023 Joseph Shook. All rights reserved.
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
    private bool _resolved;


    public FileCertificateStore(
        IOptionsMonitor<UdapFileCertStoreManifest> manifest,
        ILogger<FileCertificateStore> logger)
    {
        _manifest = manifest;
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
        communities = manifestCurrentValue.Communities;
        _logger.LogInformation("{Count} communities loaded", communities.Count);
        
        foreach (var community in communities)
        {
            var intermediates = new List<Intermediate>();
            if (community.Intermediates.Count != 0)
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

                AnchorCertificates.Add(new Anchor(new X509Certificate2(path), community.Name)
                {
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
                        _logger.LogWarning("Cannot find file: {FilePath}", path);
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
                                    _logger.LogInformation("Ignore anchor in {FilePath} certificate. Never add the anchor to anchors if not already explicitly loaded.", path);
                                }
                                else
                                {
                                    _logger.LogInformation("Found intermediate in {FilePath} certificate. Will add if not already explicitly loaded.", path);

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
                                IssuedCertificates.Add(new IssuedCertificate(x509Cert, community.Name));
                            }
                        }
                    }
                }
            }
        }
    }

}
