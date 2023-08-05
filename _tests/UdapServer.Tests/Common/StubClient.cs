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


namespace UdapServer.Tests.Common;

internal class StubClock : IClock
{
    public Func<DateTime> UtcNowFunc { get; set; } = () => DateTime.UtcNow;
    public DateTimeOffset UtcNow => new DateTimeOffset(UtcNowFunc());
}