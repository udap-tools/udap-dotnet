using NSubstitute;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Microsoft.Extensions.Logging;
using Udap.Client.Client.Messages;
using Udap.Common.Certificates;
using Xunit.Abstractions;
using System.Net;
using System.Text.Json;
using FluentAssertions;
using MartinCostello.Logging.XUnit;
using Udap.Common.Metadata;
using Udap.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Udap.Common.Tests.Client;
public class UdapClientTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly IConfigurationRoot _configuration;
    private readonly ServiceProvider _serviceProvider;

    X509ChainStatusFlags _problemFlags = X509ChainStatusFlags.NotTimeValid |
                                        X509ChainStatusFlags.Revoked |
                                        X509ChainStatusFlags.NotSignatureValid |
                                        X509ChainStatusFlags.InvalidBasicConstraints |
                                        X509ChainStatusFlags.CtlNotTimeValid |
                                        X509ChainStatusFlags.OfflineRevocation |
                                        X509ChainStatusFlags.CtlNotSignatureValid;

    public UdapClientTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            .Build();

        _serviceProvider = new ServiceCollection()
            .AddLogging(builder =>
            {
                builder.AddConfiguration(_configuration.GetSection("Logging"));
                builder.AddProvider(new XUnitLoggerProvider(_testOutputHelper, new XUnitLoggerOptions()));
                // builder.SetMinimumLevel(LogLevel.Warning); 
            })
            .BuildServiceProvider();
    }

    [Fact]
    public async Task GoodClientTest()
    {
        var udapMetadataOptions = new UdapMetadataOptions();
        _configuration.GetSection(Constants.UDAP_METADATA_OPTIONS).Bind(udapMetadataOptions);
        var unSignedMetadata = new UdapMetadata(udapMetadataOptions);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, _serviceProvider.GetRequiredService<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder(unSignedMetadata, privateCertificateStore, _serviceProvider.GetRequiredService<ILogger<UdapMetaDataBuilder>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4");

        
        var httpClientMock = Substitute.For<HttpClient>()!;
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(metadata))
        };

        httpClientMock.SendAsync(Arg.Any<HttpRequestMessage>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(response));

        var validator = new TrustChainValidator(new X509ChainPolicy(), _problemFlags, _serviceProvider.GetRequiredService<ILogger<TrustChainValidator>>())!;

        var udapClientDiscoveryValidator = Substitute.For<UdapClientDiscoveryValidator>(validator, _serviceProvider.GetRequiredService<ILogger<UdapClientDiscoveryValidator>>(), null);

        var udapClientOptions = new UdapClientOptions();
        var udapClientIOptions = Substitute.For<IOptionsMonitor<UdapClientOptions>>();
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

         IUdapClient udapClient = new UdapClient(
             httpClientMock, 
             udapClientDiscoveryValidator, 
             udapClientIOptions,
             _serviceProvider.GetRequiredService<ILogger<UdapClient>>());


         var disco = await udapClient.ValidateResource("https://localhost/fhir/r4");


         // disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
         // disco.HttpStatusCode.Should().Be(HttpStatusCode.OK);
         // Assert.NotNull(udapClient.UdapServerMetaData);
    }

    [Fact]
    public async Task CommunityTests()
    {
        var udapMetadataOptions = new UdapMetadataOptions();
        _configuration.GetSection(Constants.UDAP_METADATA_OPTIONS).Bind(udapMetadataOptions);
        var unSignedMetadata = new UdapMetadata(udapMetadataOptions);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, _serviceProvider.GetRequiredService<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder(unSignedMetadata, privateCertificateStore, _serviceProvider.GetRequiredService<ILogger<UdapMetaDataBuilder>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4");


        var httpClientMock = Substitute.For<HttpClient>()!;
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(metadata))
        };

        httpClientMock.SendAsync(Arg.Any<HttpRequestMessage>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(response));

        var validator = new TrustChainValidator(new X509ChainPolicy(), _problemFlags, _serviceProvider.GetRequiredService<ILogger<TrustChainValidator>>())!;

        var udapClientDiscoveryValidator = Substitute.For<UdapClientDiscoveryValidator>(validator, _serviceProvider.GetRequiredService<ILogger<UdapClientDiscoveryValidator>>(), null);

        var udapClientOptions = new UdapClientOptions();
        var udapClientIOptions = Substitute.For<IOptionsMonitor<UdapClientOptions>>();
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        IUdapClient udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());


        var disco = await udapClient.ValidateResource("https://localhost/fhir/r4");


        // disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        // disco.HttpStatusCode.Should().Be(HttpStatusCode.OK);
        // Assert.NotNull(udapClient.UdapServerMetaData);
    }
}
