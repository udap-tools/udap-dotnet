#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

//
// Most of this file is copied from Duende's Identity Server dom/dcr-proc branch
// 
//

using Duende.IdentityServer.Services;


namespace UdapServer.Tests.Common;

public class TestReplayCache : IReplayCache
{
    private readonly IClock _clock;
    Dictionary<string, DateTimeOffset> _values = new Dictionary<string, DateTimeOffset>();

    public TestReplayCache(IClock clock)
    {
        _clock = clock;
    }

    public Task AddAsync(string purpose, string handle, DateTimeOffset expiration)
    {
        _values[purpose + handle] = expiration;
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string purpose, string handle)
    {
        if (_values.TryGetValue(purpose + handle, out var expiration))
        {
            return Task.FromResult(_clock.UtcNow <= expiration);
        }
        return Task.FromResult(false);
    }
}

//TODO:  When Duende package is updated then this interface is in Server
public interface IClock
{
    /// <summary>
    /// The current UTC date/time.
    /// </summary>
    DateTimeOffset UtcNow { get; }
}