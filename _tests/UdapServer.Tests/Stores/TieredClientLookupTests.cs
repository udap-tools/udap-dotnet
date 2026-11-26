#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Models;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores.InMemory;

namespace UdapServer.Tests.Stores;

public class TieredClientLookupTests
{
    private static IUdapClientRegistrationStore CreateStore(params TieredClient[] clients)
    {
        return new InMemoryUdapClientRegistrationStore(new(), clients.ToList(), new List<Community>());
    }

    private static TieredClient Client(string clientId, string idp, int communityId, bool enabled = true) => new()
    {
        ClientId = clientId,
        IdPBaseUrl = idp,
        CommunityId = communityId,
        Enabled = enabled,
        ClientName = "test",
        RedirectUri = "https://server/callback",
        ClientUriSan = "https://server",
        TokenEndpoint = idp + "/connect/token"
    };

    [Fact]
    public async Task FindTieredClient_returns_only_the_registration_for_that_community()
    {
        var store = CreateStore(Client("a", "https://idp", 1), Client("b", "https://idp", 2));

        Assert.Equal("a", (await store.FindTieredClient("https://idp", 1))?.ClientId);
        Assert.Equal("b", (await store.FindTieredClient("https://idp", 2))?.ClientId);
        Assert.Null(await store.FindTieredClient("https://idp", 3));
    }

    [Fact]
    public async Task FindTieredClientById_with_idp_ignores_another_idp_that_issued_the_same_client_id()
    {
        var store = CreateStore(Client("same", "https://idp1", 1), Client("same", "https://idp2", 1));

        Assert.Equal("https://idp1", (await store.FindTieredClientById("same", "https://idp1"))?.IdPBaseUrl);
        Assert.Equal("https://idp2", (await store.FindTieredClientById("same", "https://idp2"))?.IdPBaseUrl);
        Assert.Null(await store.FindTieredClientById("same", "https://idp3"));
    }
}
