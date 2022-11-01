#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Newtonsoft.Json.Serialization;
using Newtonsoft.Json;
using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;
using program = WeatherApi.Program;

namespace Udap.Common.Tests
{
    public class ApiForCommunityTestFixture : WebApplicationFactory<program>
    {
        public ITestOutputHelper? Output { get; set; }
        private UdapMetadata? _wellKnownUdap;
        public string Community = "http://localhost";

        public UdapMetadata? WellKnownUdap
        {
            get
            {
                if (_wellKnownUdap == null)
                {
                    var response = CreateClient()
                        .GetAsync($".well-known/udap?community={Community}")
                        .GetAwaiter()
                        .GetResult();

                    response.StatusCode.Should().Be(HttpStatusCode.OK);
                    var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    _wellKnownUdap = JsonConvert.DeserializeObject<UdapMetadata>(content, new JsonSerializerSettings
                    {
                        ContractResolver = new DefaultContractResolver
                        {
                            NamingStrategy = new SnakeCaseNamingStrategy()
                        }
                    });
                }

                return _wellKnownUdap;
            }
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            //
            // Linux needs to know how to find appsettings file in web api under test.
            // Still works with Windows but what a pain.  This feels fragile
            // TODO: 
            //
            builder.UseSetting("contentRoot", "../../../../../examples/WeatherApi");
        }

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddXUnit(Output!);
            });

            return base.CreateHost(builder);
        }
    }


    public class UnitTest1 : IClassFixture<ApiForCommunityTestFixture>
    {
        private ApiForCommunityTestFixture _fixture;
        private readonly ITestOutputHelper _testOutputHelper;
        
        public UnitTest1(ApiForCommunityTestFixture fixture, ITestOutputHelper testOutputHelper)
        {
            if (fixture == null) throw new ArgumentNullException(nameof(fixture));
            fixture.Output = testOutputHelper;
            _fixture = fixture;
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void Test1()
        {
            Assert.True(File.Exists("../../../../Udap.PKI.Generator/certstores/localhost_community/anchorLocalhostCert.cer"));
        }

        [Fact] //Swagger
        public async Task OpenApiTest()
        {
            _testOutputHelper.WriteLine("Hello");
        }
    }
}

