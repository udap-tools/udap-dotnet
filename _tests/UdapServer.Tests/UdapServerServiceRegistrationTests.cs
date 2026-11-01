#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Udap.Client;

namespace UdapServer.Tests;

public class UdapServerServiceRegistrationTests
{
    /// <summary>
    /// UdapClientDiscoveryValidator keeps the server's signing certificate between ValidateJwtToken
    /// and ValidateTrustChain, so a shared instance would let concurrent Tiered OAuth challenges
    /// validate one IdP's metadata against another IdP's certificate.
    /// </summary>
    [Fact]
    public void AddUdapServer_Registers_UdapClientDiscoveryValidator_Per_Use()
    {
        var services = new ServiceCollection();

        services.AddUdapServer("https://server", "FhirLabsApi");

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(UdapClientDiscoveryValidator));
        Assert.Equal(ServiceLifetime.Transient, descriptor.Lifetime);
    }
}
