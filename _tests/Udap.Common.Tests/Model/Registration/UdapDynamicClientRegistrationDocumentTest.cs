#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Hl7.Fhir.Model;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Model.UdapAuthenticationExtensions;
using Xunit.Abstractions;
using Claim = System.Security.Claims.Claim;

namespace Udap.Common.Tests.Model.Registration;
public class UdapDynamicClientRegistrationDocumentTest
{
    private readonly ITestOutputHelper _testOutputHelper;

    public UdapDynamicClientRegistrationDocumentTest(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void ClientCredentialsFlowTest()
    {
        var expiration = TimeSpan.FromMinutes(5);
        var expirationEpochTime = EpochTime.GetIntDate(DateTime.Now.Add(expiration));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");
        
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .Build();

        document.AddClaims(new Claim[] { new("MyClaim", "Testing 123", ClaimValueTypes.String) });

        document.ClientId.Should().BeNull();
        document.Audience.Should().Be("https://securedcontrols.net/connect/register");
        document.Expiration.Should().BeCloseTo(expirationEpochTime, 3);
        document.JwtId.Should().NotBeNullOrWhiteSpace();
        document.ClientName.Should().Be("dotnet system test client");
        document.Contacts!.Count.Should().Be(2);
        document.Contacts.Should().Contain("mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com");
        document.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        document.Scope.Should().Be("system/Patient.rs system/Practitioner.read");
        document.LogoUri.Should().Be("https://avatars.githubusercontent.com/u/77421324?s=48&v=4");
        document.ResponseTypes.Should().BeEmpty();
        document.GrantTypes!.Count.Should().Be(1);
        document.GrantTypes.Should().Contain("client_credentials");

        var iat = EpochTime.DateTime(document.IssuedAt).ToUniversalTime();


        document.ClientId = "MyNewClientId"; // Simulate successful registration
        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        documentDeserialize!.ClientId.Should().Be(document.ClientId);
        documentDeserialize.Should().NotBeNullOrEmpty();
        documentDeserialize.Audience.Should().Be(document.Audience);
        documentDeserialize.Expiration.Should().Be(document.Expiration);
        documentDeserialize.JwtId.Should().Be(document.JwtId);
        documentDeserialize.ClientName.Should().Be(document.ClientName);
        documentDeserialize.Contacts.Should().Contain(document.Contacts);
        documentDeserialize.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        documentDeserialize.Scope.Should().Be(document.Scope);
        documentDeserialize.LogoUri.Should().Be(document.LogoUri);
        documentDeserialize.GrantTypes!.Count.Should().Be(1);
        documentDeserialize.SoftwareStatement.Should().Be(document.SoftwareStatement); //echo back software statement
        documentDeserialize.ResponseTypes.Should().BeEmpty();
        documentDeserialize["MyClaim"].ToString().Should().Be("Testing 123");
        documentDeserialize.IssuedAt.Should().Be(EpochTime.GetIntDate(iat));


        // Extra property coverage details
        document.Contacts = null;
        document.Extensions = null;
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        documentDeserialize!.Contacts.Should().BeEmpty();
        documentDeserialize.Extensions.Should().BeEmpty();

        //
        // Empty logo and software statement test.  Some upstream builders pass an empty logo because it is not required by client_credentials
        //
        Action buildSoftwareStatement = () => UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("")
            .BuildSoftwareStatement();

        buildSoftwareStatement.Should().NotThrow();


        Action buildSoftwareStatementRS384 = () => UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("")
            .BuildSoftwareStatement();

        buildSoftwareStatementRS384.Should().NotThrow();

    }

    [Fact]
    public void CancelRegistrationClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("")
        .Build();

        document.GrantTypes.Should().BeEmpty();
    }

    
    /// <summary>
    /// Pick another issuer that matches a SAN other than the first one in the Certificate
    /// </summary>
    [Fact]
    public void AlternateSanClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
        .Build();

        document.Issuer.Should().Be("https://fhirlabs.net:7016/fhir/r4");

        Action act = () => UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/not_here"));

        act.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Certificate does not contain a URI Subject Alternative Name of, https://fhirlabs.net:7016/fhir/not_here"));

    }

    [Fact]
    public void ControlTimesClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var issuedAt = EpochTime.GetIntDate(DateTime.Now);
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithExpiration(expiration)
            .WithIssuedAt(issuedAt)
            .Build();

        document.IssuedAt.Should().Be(issuedAt);
        document.Expiration.Should().Be(expiration);

    }
    
    [Fact]
    public void CertificateRequiredClientCredentials()
    {
        Action create = () => UdapDcrBuilderForClientCredentials
            .Create()
            .BuildSoftwareStatement();

        create.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));

        Action cancel = () => UdapDcrBuilderForClientCredentials
            .Cancel()
            .BuildSoftwareStatement();

        cancel.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));
    }

    [Fact]
    public void ErrorClientCredentialsTest()
    {
        var document = UdapDcrBuilderForClientCredentials
            .Create()
            .Build();

        document.AddClaims(new Claim[]
        {
            new Claim("error", "Poof"),
            new Claim("error_description", "Poof description")
        });

        document.GetError().Should().Be("Poof");
        document.GetErrorDescription().Should().Be("Poof description");
    }

    [Fact]
    public void ClaimClientCredentialsTest()
    {
        var document = UdapDcrBuilderForClientCredentials
            .Create()
            .Build();

        // var now = DateTime.Now.ToOADate().ToString(); 

        document.AddClaims(new Claim[]
        {
            new Claim("bool", "true", ClaimValueTypes.Boolean),
            new Claim("string", "hello", ClaimValueTypes.String),
            new Claim("double", "10.5", ClaimValueTypes.Double),
            new Claim("null", "null", JsonClaimValueTypes.JsonNull),
            // new Claim("datetime", now, ClaimValueTypes.DateTime),
            new Claim("integer64", Int64.MaxValue.ToString(), ClaimValueTypes.Integer64),
            new Claim("json", "{\"joe\":\"test\"}", JsonClaimValueTypes.Json),
            new Claim("jsonarray", "[\"one\", \"two\"]", JsonClaimValueTypes.JsonArray)
        });

        document["bool"].Should().Be(true);
        document["string"].Should().Be("hello");
        document["double"].Should().Be(10.5);
        document["null"].Should().Be("");
        document["integer64"].Should().Be(Int64.MaxValue);
        (document["json"] as JsonObject).ToJsonString().Should().Be("{\"joe\":\"test\"}");
        (document["jsonarray"] as JsonArray).ToJsonString().Should().Be("[\"one\",\"two\"]");
        // document["datetime"].Should().Be(now);
    }

    [Fact]
    public void Hl7b2bExtensionTest()
    {
        var builder = UdapDcrBuilderForClientCredentials
            .Create();

        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization|99").OriginalString;
        var organizationName = "FhirLabs";
        var purposeOfUse = new List<string>
        {
            "urn:oid:2.16.840.1.113883.5.8#TREAT"
        };
        var consentReference = new HashSet<string>
        {
            "https://fhirlabs.net/fhir/r4/Consent|99",
            "https://fhirlabs.net/fhir/r4/Consent|199"
        };
        var consentPolicy = new HashSet<string>
        {
            "https://udaped.fhirlabs.net/Policy/Consent|99",
            "https://udaped.fhirlabs.net/Policy/Consent|199"
        };

        var b2bHl7 = new B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OraganizationName = organizationName,
            PurposeOfUse = purposeOfUse,
            ConsentReference = consentReference,
            ConsentPolicy = consentPolicy, // client supplied
        };

        b2bHl7.Add("NewClaim", "Testing 123");
        
        // need to serialize to compare.
        var b2bHl7Serialized = JsonSerializer.Serialize(b2bHl7, new JsonSerializerOptions());

        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2bHl7);
        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B + "-2", b2bHl7);
        
        var document = builder.Build();

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(document, new JsonSerializerOptions(){WriteIndented = true}));
        var extentions = document.Extensions;

        extentions.Should().NotBeNull();
        extentions!.Count.Should().Be(2);
        extentions["hl7-b2b"].Should().Be(b2bHl7);
        extentions["hl7-b2b-2"].Should().Be(b2bHl7);

        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(documentDeserialize, new JsonSerializerOptions() { WriteIndented = true }));

        extentions = documentDeserialize.Extensions;

        extentions.Should().NotBeNull();
        extentions!.Count.Should().Be(2);
        extentions["hl7-b2b"].ToString().Should().BeEquivalentTo(b2bHl7Serialized);
        extentions["hl7-b2b-2"].ToString().Should().BeEquivalentTo(b2bHl7Serialized);

        var extensionSerialized = JsonSerializer.Deserialize<B2BAuthorizationExtension>(extentions["hl7-b2b"].ToString()!);
        extensionSerialized!.Version.Should().Be("1");
        extensionSerialized.SubjectId.Should().Be(subjectId);
        extensionSerialized.SubjectName.Should().Be(subjectName);
        extensionSerialized.SubjectRole.Should().Be(subjectRole);
        extensionSerialized.OrganizationId.Should().Be(organizationId);
        extensionSerialized.OraganizationName.Should().Be(organizationName);
        extensionSerialized.ConsentReference.Should().ContainInOrder(consentReference);
        extensionSerialized.PurposeOfUse.Should().ContainInOrder(purposeOfUse);
        extensionSerialized.ConsentPolicy.Should().ContainInOrder(consentPolicy);

        extensionSerialized["NewClaim"].ToString().Should().Be("Testing 123");
        extensionSerialized.Should().NotContainKey("MissingClaim");

        b2bHl7 = new B2BAuthorizationExtension()
        {
            SubjectId = subjectId
        };

        builder = UdapDcrBuilderForClientCredentials.Create();
        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2bHl7);
        document = builder.Build();
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        extensionSerialized = JsonSerializer.Deserialize<B2BAuthorizationExtension>(documentDeserialize!.Extensions!["hl7-b2b"].ToString()!);
        extensionSerialized!.SubjectName.Should().BeNull();
        extensionSerialized.ConsentReference.Should().BeEmpty();
    }

    [Fact]
    public void ClaimAuthorizationCodeFlowTest()
    {
        var document = UdapDcrBuilderForClientCredentials
            .Create()
            .Build();

        // var now = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"); 

        document.AddClaims(new Claim[]
        {
            new Claim("bool", "true", ClaimValueTypes.Boolean),
            new Claim("string", "hello", ClaimValueTypes.String),
            new Claim("double", "10.5", ClaimValueTypes.Double),
            new Claim("null", "null", JsonClaimValueTypes.JsonNull),
            // new Claim("datetime", now, ClaimValueTypes.DateTime),
        });

        document["bool"].Should().Be(true);
        document["string"].Should().Be("hello");
        document["double"].Should().Be(10.5);
        document["null"].Should().Be("");
        // document["datetime"].Should().Be(now);
    }


    [Fact]
    public void AuthorizationCodeFlowTest()
    {
        var expiration = TimeSpan.FromMinutes(5);
        var expirationEpochTime = EpochTime.GetIntDate(DateTime.Now.Add(expiration));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .Build();

        document.AddClaims(new Claim[] { new Claim("MyClaim", "Testing 123") });

        document.ClientId.Should().BeNull();
        document.Audience.Should().Be("https://securedcontrols.net/connect/register");
        document.Expiration.Should().BeCloseTo(expirationEpochTime, 3);
        document.JwtId.Should().NotBeNullOrWhiteSpace();
        document.ClientName.Should().Be("dotnet system test client");
        document.Contacts!.Count.Should().Be(2);
        document.Contacts.Should().Contain("mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com");
        document.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        document.Scope.Should().Be("system/Patient.rs system/Practitioner.read");
        document.ResponseTypes.Should().Contain("code");
        document.Issuer.Should().Be("https://fhirlabs.net/fhir/r4"); // same as first subject alternative name
        document.RedirectUris!.Count.Should().Be(1);
        document.RedirectUris.Should().Contain("https://client.fhirlabs.net/redirect/");
        document.LogoUri.Should().Be("https://avatars.githubusercontent.com/u/77421324?s=48&v=4");
        document.GrantTypes!.Count.Should().Be(1);
        document.GrantTypes.Should().Contain("authorization_code");

        var signedDocument = SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(clientCert, document).Build();

        document.SoftwareStatement = signedDocument;
        document.ClientId = "MyNewClientId"; // Simulate successful registration
        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        documentDeserialize!.ClientId.Should().Be(document.ClientId);
        documentDeserialize.Should().NotBeNullOrEmpty();
        documentDeserialize.Audience.Should().Be(document.Audience);
        documentDeserialize.Expiration.Should().Be(document.Expiration);
        documentDeserialize.JwtId.Should().Be(document.JwtId);
        documentDeserialize.ClientName.Should().Be(document.ClientName);
        documentDeserialize.Contacts.Should().ContainInOrder(document.Contacts);
        documentDeserialize.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        documentDeserialize.Scope.Should().Be(document.Scope);
        documentDeserialize.SoftwareStatement.Should().NotBeNullOrWhiteSpace();
        documentDeserialize.SoftwareStatement.Should().Be(document.SoftwareStatement); //echo back software statement
        documentDeserialize.ResponseTypes.Should().ContainInOrder(document.ResponseTypes);
        documentDeserialize.Issuer.Should().Be(document.Issuer);
        documentDeserialize.RedirectUris.Should().ContainInOrder(document.RedirectUris);
        documentDeserialize.LogoUri.Should().Be(document.LogoUri);
        documentDeserialize.GrantTypes!.Count.Should().Be(1);
        documentDeserialize.GrantTypes.Should().Contain(document.GrantTypes);
        documentDeserialize["MyClaim"].ToString().Should().Be("Testing 123");

        // Extra property coverage details
        document.Contacts = null;
        document.ResponseTypes = null;
        document.GrantTypes = null;
        document.RedirectUris = null;
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        documentDeserialize!.Contacts.Should().BeEmpty();
        documentDeserialize.ResponseTypes.Should().BeEmpty();
        documentDeserialize.GrantTypes.Should().BeEmpty();
        documentDeserialize.RedirectUris.Should().BeEmpty();

        // What might happen on responding from Server
        var _ = new UdapDynamicClientRegistrationDocument()
        {
            ClientId = document.ClientId,
            SoftwareStatement = document.SoftwareStatement
        };

        Action act = () => new UdapDynamicClientRegistrationDocument()
        {
            ClientId = document.ClientId,
            SoftwareStatement = null
        };

        act.Should().NotThrow();


        Action buildSoftwareStatement = () => UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .BuildSoftwareStatement();

        buildSoftwareStatement.Should().NotThrow();

        Action buildSoftwareStatementRS384 = () => UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .BuildSoftwareStatement(UdapConstants.SupportedAlgorithm.RS384);

        buildSoftwareStatementRS384.Should().NotThrow();
    }

    /// <summary>
    /// Pick another issuer that matches a SAN other than the first one in the Certificate
    /// </summary>
    [Fact]
    public void AlternateSanAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .Build();

        document.Issuer.Should().Be("https://fhirlabs.net:7016/fhir/r4");

        Action act = () => UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/not_here"));

        act.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Certificate does not contain a URI Subject Alternative Name of, https://fhirlabs.net:7016/fhir/not_here"));
    }

    [Fact]
    public void CancelRegistrationAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Cancel(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .Build();

        document.GrantTypes.Should().BeEmpty();
    }

    [Fact]
    public void ControlTimesAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var issuedAt = EpochTime.GetIntDate(DateTime.Now);
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithExpiration(expiration)
            .WithIssuedAt(issuedAt)
            .Build();

        document.IssuedAt.Should().Be(issuedAt);
        document.Expiration.Should().Be(expiration);

    }
    [Fact]
    public void AuthorizationCodeFlowSetResponseTypeTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");
        
        var documentAuthCode = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithResponseTypes(new HashSet<string>(){"code", "secret"})
            .Build();

        documentAuthCode.ResponseTypes.Should().ContainInOrder(new HashSet<string>() { "code", "secret" });
    }

    [Fact]
    public void CertificateRequiredAuthorizationCodeTest()
    {
        Action create = () => UdapDcrBuilderForAuthorizationCode
            .Create()
            .BuildSoftwareStatement();

        create.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));

        Action cancel = () => UdapDcrBuilderForAuthorizationCode
            .Cancel()
            .BuildSoftwareStatement();

        cancel.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));
    }

    [Fact]
    public void ErrorAuthorizationCodeFlowTest()
    {
        var document = UdapDcrBuilderForAuthorizationCode
            .Create()
            .Build();

        document.AddClaims(new Claim[]
        {
            new Claim("error", "Poof"),
            new Claim("error_description", "Poof description")
        });

        document.GetError().Should().Be("Poof");
        document.GetErrorDescription().Should().Be("Poof description");
    }
}
