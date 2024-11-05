#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


//
// This code was inspired from Duende Identity Server Tests
//

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.



using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Options;
using Duende.IdentityServer.EntityFramework.Stores;
using Duende.IdentityServer.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace UdapServer.Tests.EntityFramework.Stores;

public class ClientStoreTests : StorageFixture<ClientStoreTests, ConfigurationDbContext, ConfigurationStoreOptions>
{
    public ClientStoreTests(TestDatabaseProvider<ConfigurationDbContext> fixture) : base(fixture)
    {
        var optionsList = new List<DbContextOptions<ConfigurationDbContext>>();

        foreach (var options in TestDatabaseProviders)
        {
            optionsList.Add((DbContextOptions<ConfigurationDbContext>)options);
        }

        foreach (var options in optionsList)
        {
            using var context = new ConfigurationDbContext(options);
            context.Database.EnsureCreated();
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabaseProviders))]
    public async Task FindClientByIdAsync_WhenClientDoesNotExist_ExpectNull(DbContextOptions<ConfigurationDbContext> options)
    {
        await using var context = new ConfigurationDbContext(options);

        //
        // Note concerning NoneCancellationTokenProvider() that implements ICancellationTokenProvider.
        // The DefaultHttpContextCancellationTokenICancellationTokenProvider implementation is injected into IdentityServer
        // and takes a IHttpContextAccessor where the HttpContext.RequestAborted can be checked.
        // It is not apparent where this is in a test.  But commented because I originally sent in default.  
        // It failed with null object and it was difficult to troubleshoot because the failure was in a IQueriable call
        // so the actual failure was many lines below where the debugger blows up in FindClientByIdAsync.
        //

        var store = new ClientStore(context, Substitute.For<ILogger<ClientStore>>(), new NoneCancellationTokenProvider());
        var client = await store.FindClientByIdAsync(Guid.NewGuid().ToString());
        client.Should().BeNull();
    }
}