using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UdapServer.Tests.Conformance.Basic;

public class ClientCredentialsUdapModeTests
{
    private const string Category = "Conformance.Basic.UdapClientCredentialsTests";

    [Fact]
    [Trait("Category", Category)]
    public async Task Todo()
    {
        //Need tests here:

        // Ensure the missing scope test during /connect/token request works
        // It should test in UDAP server mode and specifically UdapScopeResolverMiddleware and 
    }
}