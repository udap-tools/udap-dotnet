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
using program = FhirLabsApi.Program;

namespace Udap.Common.Tests.FhirLabs
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
            builder.UseSetting("contentRoot", "../../../../../examples/FhirLabsApi");
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


            var response = await _fixture.CreateClient().GetAsync($"fhir/r4/Swagger/Index.html");

            System.Diagnostics.Trace.WriteLine(response.ToString());

            response.StatusCode.Should().Be(HttpStatusCode.OK, "Should be status ok");
            var contentType = response.Content.Headers.ContentType;
            contentType.Should().NotBeNull();
            contentType!.MediaType.Should().Be("text/html", "Should be status ok");

            var result = await response.Content.ReadAsStringAsync();
            result
                .Should()
                .Contain(
                    "./swagger-ui.css",
                    "Does not seem to be the standard swagger ui html");

            //
            // TODO
            // This last part doesn't actually catch failures.  I would need to render the html 
            // some how to finish the test.
            // To make this fail just change one of the helper methods in udapController from
            // private to public.


            result
                .Should()
                .NotContain(
                    "Failed to load API definition",
                    "Swagger UI Failed to load.");
        }
    }
}

