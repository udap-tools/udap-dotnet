using Duende.IdentityServer.Models;

namespace Udap.Auth.Server;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        { 
            new IdentityResources.OpenId()
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
            { };

    public static IEnumerable<Duende.IdentityServer.Models.Client> Clients =>
        new Duende.IdentityServer.Models.Client[] 
            { };
}