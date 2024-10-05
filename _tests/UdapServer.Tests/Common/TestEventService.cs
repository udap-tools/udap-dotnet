#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// Original code from:
// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using FluentAssertions;

namespace UdapServer.Tests.Common;

public class TestEventService : IEventService
{
    private readonly Dictionary<Type, object> _events = new Dictionary<Type, object>();

    public Task RaiseAsync(Event evt)
    {
        _events.Add(evt.GetType(), evt);
        return Task.CompletedTask;
    }

    public T AssertEventWasRaised<T>()
        where T : class
    {
        _events.ContainsKey(typeof(T)).Should().BeTrue();
        return (T)_events.Where(x => x.Key == typeof(T)).Select(x=>x.Value).First();
    }

    public bool CanRaiseEventType(EventTypes evtType)
    {
        return true;
    }
}