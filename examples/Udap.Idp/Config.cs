using Duende.IdentityServer.Models;

namespace Udap.Idp;

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