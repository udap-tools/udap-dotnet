#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using FluentAssertions;
using MartinCostello.Logging.XUnit;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Common.Metadata;
using Udap.Model;
using Xunit.Abstractions;

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
                                        // X509ChainStatusFlags.OfflineRevocation | Do not test revocation in unit tests
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

    /// <summary>
    /// Test with just the basics.  Some good comments to see how all the parts fit together
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task StandardSuccessTest()
    {
        //
        // Metadata for describing different UDAP metadata per community
        //
        var udapMetadataOptions = new UdapMetadataOptions();
        _configuration.GetSection(Constants.UDAP_METADATA_OPTIONS).Bind(udapMetadataOptions);
        var unSignedMetadata = new UdapMetadata(udapMetadataOptions);

        // TODO:  Make scope configuration first class in DI
        unSignedMetadata.ScopesSupported = new List<string>
        {
            "openid", "patient/*.read", "user/*.read", "system/*.read", "patient/*.rs", "user/*.rs", "system/*.rs"
        };



        //
        // Certificate store metadata
        //
        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(udapFileCertStoreManifest);
        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        //
        // IPrivateCertificateStore implementation as a file store
        //
        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, _serviceProvider.GetRequiredService<ILogger<IssuedCertificateStore>>());

        //
        // MetadataBuilder helps build signed UDAP metadata using the previous metadata and IPrivateCertificateStore implementation
        //
        var metaDataBuilder = new UdapMetaDataBuilder(unSignedMetadata, privateCertificateStore, _serviceProvider.GetRequiredService<ILogger<UdapMetaDataBuilder>>());
        var signedMetadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4");

        //
        // Mock an HttpClient used by UdapClient.  The mock will return the signed Metadata rather than rely on aa UDAP Metadata service.
        //
        var httpClientMock = Substitute.For<HttpClient>()!;
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(signedMetadata))
        };
        httpClientMock.SendAsync(Arg.Any<HttpRequestMessage>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(response));

        //
        // TrustChainValidator handle the x509 chain building, policy and validation
        //
        var validator = new TrustChainValidator(new X509ChainPolicy(), _problemFlags, _serviceProvider.GetRequiredService<ILogger<TrustChainValidator>>())!;

        //
        // TrustAnchorStore is using an ITrustAnchorStore implemented as a file store.
        //
        var trustAnchorStore = new TrustAnchorFileStore(udapFileCertStoreManifestOptions, _serviceProvider.GetRequiredService<ILogger<TrustAnchorFileStore>>());

        //
        // UdapClientDiscoveryValidator orchestrates JWT validation followed by x509 chain validation used by UdapClient
        //
        var udapClientDiscoveryValidator = Substitute.For<UdapClientDiscoveryValidator>(
            validator,
            _serviceProvider.GetRequiredService<ILogger<UdapClientDiscoveryValidator>>(),
            trustAnchorStore);

        //
        // Options for setting your client name, contacts, logo and HTTP headers.
        //
        var udapClientOptions = new UdapClientOptions();
        var udapClientIOptions = Substitute.For<IOptionsMonitor<UdapClientOptions>>();
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        //
        // The actual UdapClient.  There are two examples of using it in the _tests/client folder
        //
        IUdapClient udapClient = new UdapClient(
             httpClientMock,
             udapClientDiscoveryValidator,
             udapClientIOptions,
             _serviceProvider.GetRequiredService<ILogger<UdapClient>>());


        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4");

        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        disco.HttpStatusCode.Should().Be(HttpStatusCode.OK);
        Assert.NotNull(udapClient.UdapServerMetaData);


        //
        // Various properties asserted
        // These tests are also in the Udap.Metadata tests.  Those tests are integration and only cover the Framework version of the current web service.
        // These tests are easier to test against all the current framework versions.  For example currently this test is testing .Net 6, 7 and 8
        // ensuring we get good coverage
        //
        var verSupported = disco.UdapVersionsSupported.ToList();
        verSupported.Should().NotBeNullOrEmpty();
        verSupported.Single().Should().Be("1");


        var extensions = disco.UdapAuthorizationExtensionsSupported.ToList();
        extensions.Should().NotBeNullOrEmpty();
        var hl7B2B = extensions.SingleOrDefault(c => c == "hl7-b2b");
        hl7B2B.Should().NotBeNullOrEmpty();


        disco.UdapAuthorizationExtensionsRequired.Should().Contain("hl7-b2b");


        var certificationsSupported = disco.UdapCertificationsSupported.SingleOrDefault(c => c == "http://MyUdapCertification");
        certificationsSupported.Should().NotBeNullOrEmpty();
        var uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification");


        certificationsSupported = disco.UdapCertificationsSupported.SingleOrDefault(c => c == "http://MyUdapCertification2");
        certificationsSupported.Should().NotBeNullOrEmpty();
        uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification2");


        var certificationsRequired = disco.UdapCertificationsRequired.SingleOrDefault();
        certificationsRequired.Should().NotBeNullOrEmpty();
        var uriCertificationsRequired = new Uri(certificationsRequired!);
        uriCertificationsRequired.Should().Be("http://MyUdapCertification");


        var grantTypes = disco.GrantTypesSupported.ToList();
        grantTypes.Should().NotBeNullOrEmpty();
        grantTypes.Count().Should().Be(3);
        grantTypes.Should().Contain("authorization_code");
        grantTypes.Should().Contain("refresh_token");
        grantTypes.Should().Contain("client_credentials");


        var scopesSupported = disco.ScopesSupported.ToList();
        scopesSupported.Should().Contain("openid");
        scopesSupported.Should().Contain("system/*.read");
        scopesSupported.Should().Contain("user/*.read");
        scopesSupported.Should().Contain("patient/*.read");


        var authorizationEndpoint = disco.AuthorizeEndpoint;
        authorizationEndpoint.Should().Be("https://securedcontrols.net:5001/connect/authorize");


        var tokenEndpoint = disco.TokenEndpoint;
        tokenEndpoint.Should().Be("https://securedcontrols.net:5001/connect/token");


        var registrationEndpoint = disco.RegistrationEndpoint;
        registrationEndpoint.Should().Be("https://securedcontrols.net:5001/connect/register");


        var tokenEndpointAuthMethodSupported = disco.TokenEndpointAuthMethodsSupported.SingleOrDefault();
        tokenEndpointAuthMethodSupported.Should().NotBeNullOrEmpty();
        tokenEndpointAuthMethodSupported.Should().Be("private_key_jwt");


        var registrationSigningAlgValuesSupported = disco.RegistrationEndpointJwtSigningAlgValuesSupported.ToList();
        registrationSigningAlgValuesSupported.Should().NotBeNullOrEmpty();
        registrationSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS256);
        registrationSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS384);
        registrationSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.ES256);
        registrationSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.ES384);
        registrationSigningAlgValuesSupported.Count().Should().Be(4);



        var tokenSigningAlgValuesSupported = disco.TokenEndpointAuthSigningAlgValuesSupported.ToList();
        tokenSigningAlgValuesSupported.Should().NotBeNullOrEmpty();
        tokenSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS256);
        tokenSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS384);
        tokenSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.ES256);
        tokenSigningAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.ES384);
        tokenSigningAlgValuesSupported.Count().Should().Be(4);

        var profilesSupported = disco.UdapProfilesSupported.ToList();
        profilesSupported.Should().NotBeNullOrEmpty();
        profilesSupported.Should().Contain(UdapConstants.UdapProfilesSupportedValues.UdapDcr);
        profilesSupported.Should().Contain(UdapConstants.UdapProfilesSupportedValues.UdapAuthn);
        profilesSupported.Should().Contain(UdapConstants.UdapProfilesSupportedValues.UdapAuthz);

        //
        // Checking the SignedMetadata
        //

        var jwt = new JwtSecurityToken(disco.SignedMetadata);
        var tokenHeader = jwt.Header;

        var x5CArray = tokenHeader["x5c"] as List<object>;
    }
}
