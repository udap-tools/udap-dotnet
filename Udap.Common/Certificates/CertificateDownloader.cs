#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Certificates;

/// <summary>
/// Downloads for AIA and CRL URLs. Those URLs come from certificates, which may have been
/// written by whoever is asking to be trusted, so only http and https are fetched and the
/// response size is capped instead of buffering whatever the server sends.
/// </summary>
internal static class CertificateDownloader
{
    /// <summary>Largest certificate accepted from an AIA "CA Issuers" URL.</summary>
    internal const int MaxCertificateBytes = 1024 * 1024;

    /// <summary>Largest CRL accepted from a CRL distribution point.</summary>
    internal const int MaxCrlBytes = 20 * 1024 * 1024;

    internal static bool IsHttpUrl(string? url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uri)
               && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }

    internal static async Task<byte[]> GetBytesAsync(HttpClient httpClient, string url, int maxBytes, CancellationToken cancellationToken)
    {
        if (!IsHttpUrl(url))
        {
            throw new InvalidOperationException($"Only http and https URLs are downloaded: {url}");
        }

        using var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new InvalidOperationException($"Response from {url} is larger than {maxBytes} bytes");
        }

        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;

        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                throw new InvalidOperationException($"Response from {url} is larger than {maxBytes} bytes");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
