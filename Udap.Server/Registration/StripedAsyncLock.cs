#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Registration;

/// <summary>
/// Serializes work that shares a key within this process, for check-then-write sequences that the database cannot
/// make atomic. A fixed number of stripes bounds memory; unrelated keys that share a stripe only wait for each other.
/// This does not coordinate between server instances.
/// </summary>
internal static class StripedAsyncLock
{
    private const int StripeCount = 64;

    private static readonly SemaphoreSlim[] Stripes =
        Enumerable.Range(0, StripeCount).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    public static async Task<IDisposable> AcquireAsync(string key, CancellationToken token)
    {
        var stripe = Stripes[(StringComparer.Ordinal.GetHashCode(key) & 0x7fffffff) % StripeCount];
        await stripe.WaitAsync(token);
        return new Releaser(stripe);
    }

    private sealed class Releaser(SemaphoreSlim stripe) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                stripe.Release();
            }
        }
    }
}
