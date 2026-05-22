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

/// <summary>
/// File-based implementation of <see cref="ICertificateStore"/> that loads trust anchors and
/// issued certificates from PFX/CER files specified in the <see cref="UdapFileCertStoreManifest"/>.
/// Supports hot-reload via <see cref="IOptionsMonitor{T}"/>.
/// </summary>
public class FileCertificateStore : ICertificateStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private readonly ILogger<FileCertificateStore> _logger;
    private bool _resolved;

    /// <summary>
    /// Initializes a new instance of the <see cref="FileCertificateStore"/>.
    /// </summary>
    /// <param name="manifest">The monitored certificate store manifest configuration.</param>
    /// <param name="logger">The logger instance.</param>
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

    /// <inheritdoc />
    public Task<ICertificateStore> Resolve()
    {
        if (_resolved == false)
        {
            LoadCertificates(_manifest.CurrentValue);
        }
        _resolved = true;

        return Task.FromResult(this as ICertificateStore);
    }

    /// <inheritdoc />
    public ICollection<Anchor> AnchorCertificates { get; set; } = new HashSet<Anchor>();

    /// <inheritdoc />
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
#if NET9_0_OR_GREATER
                    intermediates.Add(new Intermediate(X509CertificateLoader.LoadCertificateFromFile(Path.Combine(AppContext.BaseDirectory, intermediateFilePath))));
#else
                    intermediates.Add(new Intermediate(new X509Certificate2(Path.Combine(AppContext.BaseDirectory, intermediateFilePath))));
#endif
                }
            }

            foreach (var communityAnchor in community.Anchors)
            {
                if (communityAnchor.FilePath == null)
                {
                    throw new InvalidOperationException($"Missing file path in one of the anchors in {nameof(community.Anchors)}");
                }

                var path = Path.Combine(AppContext.BaseDirectory, communityAnchor.FilePath);

                if (!File.Exists(path))
                {
                    throw new FileNotFoundException($"Cannot find file: {path}");
                }

#if NET9_0_OR_GREATER
                AnchorCertificates.Add(new Anchor(X509CertificateLoader.LoadCertificateFromFile(path), community.Name)
#else
                AnchorCertificates.Add(new Anchor(new X509Certificate2(path), community.Name)
#endif
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

#if NET9_0_OR_GREATER
                    var certificates = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, communityIssuer.Password, X509KeyStorageFlags.Exportable);
#else
                    var certificates = new X509Certificate2Collection();
                    certificates.Import(path, communityIssuer.Password, X509KeyStorageFlags.Exportable);
#endif

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
