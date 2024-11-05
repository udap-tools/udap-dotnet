using Duende.IdentityServer.Models;

namespace Udap.Auth.Server;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        [ 
            new IdentityResources.OpenId()
        ];

    public static IEnumerable<ApiScope> ApiScopes =>
        [];

    public static IEnumerable<Duende.IdentityServer.Models.Client> Clients =>
        [];
}