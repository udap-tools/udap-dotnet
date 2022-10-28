#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Udap.Server.Registration;
using Xunit.Abstractions;

namespace UdapServer.Tests
{
    public  class RegistrationTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public RegistrationTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void UdapMemoryServerConfiguration()
        {
            var services = new ServiceCollection();
            services.AddIdentityServer()
                .AddUdapServerConfiguration();
            services.AddTransient<IUdapClientConfigurationStore, UdapClientConfigurationStore>();
            services.AddTransient<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        }
    }
}
