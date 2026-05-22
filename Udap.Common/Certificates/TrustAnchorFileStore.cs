#region (c) 2023 Joseph Shook. All rights reserved.
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
using Udap.Common.Models;

namespace Udap.Common.Certificates;

/// <summary>
/// File-based implementation of <see cref="ITrustAnchorStore"/> that loads trust anchor
/// certificates from CER files specified in the <see cref="UdapFileCertStoreManifest"/>.
/// Supports hot-reload via <see cref="IOptionsMonitor{T}"/>.
/// </summary>
public class TrustAnchorFileStore : ITrustAnchorStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private readonly ILogger<TrustAnchorFileStore> _logger;
    private bool _resolved;

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustAnchorFileStore"/>.
    /// </summary>
    /// <param name="manifest">The monitored certificate store manifest configuration.</param>
    /// <param name="logger">The logger instance.</param>
    public TrustAnchorFileStore(
        IOptionsMonitor<UdapFileCertStoreManifest> manifest,
        ILogger<TrustAnchorFileStore> logger)
    {
        _manifest = manifest;
        _logger = logger;

        _manifest.OnChange(_ =>
        {
            _resolved = false;
        });
    }

    /// <inheritdoc />
    public Task<ITrustAnchorStore> Resolve()
    {
        if (_resolved == false)
        {
            LoadCertificates(_manifest.CurrentValue);
        }
        _resolved = true;

        return Task.FromResult(this as ITrustAnchorStore);
    }

    /// <inheritdoc />
    public ICollection<Anchor> AnchorCertificates { get; set; } = new HashSet<Anchor>();

    // TODO convert to Lazy<T> to protect from race conditions
    private void LoadCertificates(UdapFileCertStoreManifest manifestCurrentValue)
    {
       var communities = manifestCurrentValue.Communities;

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
        }
    }

}