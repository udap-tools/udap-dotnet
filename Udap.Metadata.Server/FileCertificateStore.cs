#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Udap.Common;
using Udap.Common.Extensions;
using Udap.Common.Models;

namespace Udap.Metadata.Server;

public class FileCertificateStore : ICertificateStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private string _resourceServerName;
    private bool _resolved;

    public FileCertificateStore(IOptionsMonitor<UdapFileCertStoreManifest> manifest, string resourceServerName)
    {
        _manifest = manifest;
        _resourceServerName = resourceServerName;

        _manifest.OnChange(_ =>
        {
            _resolved = false;
        });
    }
    public ICertificateStore Resolve()
    {
        if (_resolved == false)
        {
            LoadCertificates(_manifest.CurrentValue);
        }
        _resolved = true;

        return this;
    }

    public ICollection<X509Certificate2> RootCAs { get; set; } = new HashSet<X509Certificate2>();

    public ICollection<Anchor> Anchors { get; set; } = new HashSet<Anchor>();
    public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new HashSet<IssuedCertificate>();

    // TODO convert to Lazy<T> to protect from race conditions

    private void LoadCertificates(UdapFileCertStoreManifest manifestCurrentValue)
    {
        var communities = manifestCurrentValue
            .ResourceServers
            .SingleOrDefault(r => r.Name == _resourceServerName)
            ?.Communities;
        
        if (communities == null) return;

        foreach (var community in communities)
        {
            if (community.RootCAFilePaths.Any())
            {
                foreach (var communityRootCaFilePath in community.RootCAFilePaths)
                {
                    RootCAs.Add(new X509Certificate2(Path.Combine(AppContext.BaseDirectory, communityRootCaFilePath)));
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

                Anchors.Add(new Anchor(new X509Certificate2(path))
                {
                    Community = community.Name,
                });
            }

            foreach (var communityIssuer in community.IssuedCerts)
            {
                if (communityIssuer.FilePath == null)
                {
                    throw new Exception($"Missing file path in on of the anchors {nameof(community.IssuedCerts)}");
                }

                var path = Path.Combine(AppContext.BaseDirectory, communityIssuer.FilePath);

                if (!File.Exists(path))
                {
                    throw new FileNotFoundException($"Cannot find file: {path}");
                }
                
                var certificates = new X509Certificate2Collection();
                certificates.Import(path, communityIssuer.Password);
                
                foreach (var cert in certificates)
                {
                    var extension = cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.19") as X509BasicConstraintsExtension;
                    var subjectIdentifier = cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.14") as X509SubjectKeyIdentifierExtension;
                    
                    //
                    // dotnet 7.0
                    //
                    // var authorityIdentifier = cert.Extensions.FirstOrDefault(e => e.Oid.Value == "2.5.29.35") as X509AuthorityKeyIdentifierExtension;
                    
                    string? authorityIdentifierValue = null;

                    Asn1Object? exValue = cert.GetExtensionValue("2.5.29.35");
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
                                RootCAs.Add(cert);
                            }
                            else
                            {
                                Anchors.Add(new Anchor(cert) { Community = community.Name });
                            }
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

