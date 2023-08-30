// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


namespace Udap.Server.Infrastructure.Clock;


//TODO:  When a future Duende package is release then this interface is in Server
/// <summary>
/// Abstraction for the date/time.
/// </summary>
public interface IClock
{
    /// <summary>
    /// The current UTC date/time.
    /// </summary>
    DateTimeOffset UtcNow { get; }
}
