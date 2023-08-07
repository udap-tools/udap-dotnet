// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


namespace Udap.Server.Infrastructure.Clock;

#if NET8_0_OR_GREATER

class DefaultClock : IClock
{
    private readonly TimeProvider _timeProvider;

    public DefaultClock()
    {
        _timeProvider = TimeProvider.System;
    }

    public DefaultClock(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
    }

    public DateTimeOffset UtcNow { get => _timeProvider.GetUtcNow(); }
}

#endif
