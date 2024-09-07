#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using System.Reflection.Metadata;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Model.UdapAuthenticationExtensions;
using Xunit.Abstractions;
using Xunit.Sdk;
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

    /// <summary>
    /// Without builder
    /// </summary>
    [Fact]
    public void TestHl7b2bExtensionSerialization()
    {
        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization/99").OriginalString;
        var organizationName = "FhirLabs";

        var hl7b2b = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName
        };

        hl7b2b.PurposeOfUse.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        hl7b2b.ConsentPolicy.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7b2b.ConsentReference.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        var serializeDocument = hl7b2b.SerializeToJson();

        serializeDocument.Should().Contain("urn:oid:2.16.840.1.113883.5.8#TREAT");
        serializeDocument.Should().Contain("https://udaped.fhirlabs.net/Policy/Consent/99");
        serializeDocument.Should().Contain("https://fhirlabs.net/fhir/r4/Consent/99");


        hl7b2b.PurposeOfUse.Remove("urn:oid:2.16.840.1.113883.5.8#TREAT").Should().BeTrue();
        hl7b2b.PurposeOfUse.Any().Should().BeFalse();

        hl7b2b = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(hl7b2b.SerializeToJson());
        hl7b2b.PurposeOfUse.Any().Should().BeFalse();
    }

    /// <summary>
    /// Without builder
    /// </summary>
    [Fact]
    public void TestHl7b2bUserExtensionSerialization()
    {
        var userPersonJson = File.ReadAllText("Model/Person-FASTIDUDAPPerson-Example.json");
        var parser = new FhirJsonParser();
        var personResource = parser.Parse<Person>(userPersonJson);
        personResource.Should().NotBeNull();
        var serializer = new FhirJsonSerializer();
        var userPerson = serializer.SerializeToString(personResource);
        userPerson.Should().NotBeNullOrEmpty();

        JsonElement userPersonElement;
        using (var jasonDocument = JsonDocument.Parse(userPerson))
        {
            userPersonElement = jasonDocument.RootElement.Clone();
        }

        var hl7b2bUser = new HL7B2BUserAuthorizationExtension()
        {
            UserPerson = userPersonElement,
        };

        hl7b2bUser.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        hl7b2bUser.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7b2bUser.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        var serializeDocument = hl7b2bUser.SerializeToJson();

        serializeDocument.Should().Contain("urn:oid:2.16.840.1.113883.5.8#TREAT");
        serializeDocument.Should().Contain("https://udaped.fhirlabs.net/Policy/Consent/99");
        serializeDocument.Should().Contain("https://fhirlabs.net/fhir/r4/Consent/99");

        hl7b2bUser = JsonSerializer.Deserialize<HL7B2BUserAuthorizationExtension>(serializeDocument);

        hl7b2bUser.PurposeOfUse.Remove("urn:oid:2.16.840.1.113883.5.8#TREAT").Should().BeTrue();
        hl7b2bUser.PurposeOfUse.Any().Should().BeFalse();

        hl7b2bUser.ConsentPolicy?.Remove("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7b2bUser.ConsentPolicy?.Any().Should().BeFalse();

        hl7b2bUser.SerializeToJson().Should().NotContain("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7b2bUser = JsonSerializer.Deserialize<HL7B2BUserAuthorizationExtension>(hl7b2bUser.SerializeToJson());
        hl7b2bUser?.ConsentPolicy?.Any().Should().BeFalse();
    }

    /// <summary>
    /// Without builder
    /// </summary>
    [Fact]
    public void TestTefcaIASExtensionSerialization()
    {
        var relatedPersonJson = File.ReadAllText("Model/RelatedPersonExample.json");
        var relatedPersonResource = new FhirJsonParser().Parse<RelatedPerson>(relatedPersonJson);
        relatedPersonResource.Should().NotBeNull();
        var relatedPerson = new FhirJsonSerializer(new SerializerSettings(){Pretty = false}).SerializeToString(relatedPersonResource);
        relatedPerson.Should().NotBeNullOrEmpty();

        JsonElement relatedPersonElement;
        using (var jasonDocument = JsonDocument.Parse(relatedPerson))
        {
            relatedPersonElement = jasonDocument.RootElement.Clone();
        }

        var patientJson = File.ReadAllText("Model/PatientExample.json");
        var patientResource = new FhirJsonParser().Parse<Patient>(patientJson);
        relatedPersonResource.Should().NotBeNull();
        var patient = new FhirJsonSerializer(new SerializerSettings(){Pretty = false}).SerializeToString(patientResource);
        patient.Should().NotBeNullOrEmpty();

        JsonElement patientElement;
        using (var jasonDocument = JsonDocument.Parse(patient))
        {
            patientElement = jasonDocument.RootElement.Clone();
        }

        var exampleIdentityToken = "{\r\n\"iss\": \"https://example.com\",\r\n  \"sub\": \"user123\",\r\n  \"aud\": \"client123\",\r\n  \"exp\": 1672531200,\r\n  \"iat\": 1672444800,\r\n  \"jti\": \"abc123\"\r\n}";

        JsonElement identityTokenElement;
        using (var jasonDocument = JsonDocument.Parse(exampleIdentityToken))
        {
            identityTokenElement = jasonDocument.RootElement.Clone();
        }

        var tefcaIas = new TEFCAIASAuthorizationExtension()
        {
            UserInformation = relatedPersonElement,
            PatientInformation = patientElement,
            IalVetted = identityTokenElement,
            IdToken = identityTokenElement
        };

        tefcaIas.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        tefcaIas.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        tefcaIas.Validate().Should().BeEmpty();

        var serializeDocument = tefcaIas.SerializeToJson(true);

        // _testOutputHelper.WriteLine(serializeDocument);
   

        serializeDocument.Should().Contain("T-IAS");
        serializeDocument.Should().Contain("https://udaped.fhirlabs.net/Policy/Consent/99");
        serializeDocument.Should().Contain("https://fhirlabs.net/fhir/r4/Consent/99");

        tefcaIas = JsonSerializer.Deserialize<TEFCAIASAuthorizationExtension>(serializeDocument);

        tefcaIas.PurposeOfUse.Should().Be("T-IAS");

        tefcaIas.ConsentPolicy?.Remove("https://udaped.fhirlabs.net/Policy/Consent/99");
        tefcaIas.ConsentPolicy?.Any().Should().BeFalse();

        tefcaIas.SerializeToJson().Should().NotContain("https://udaped.fhirlabs.net/Policy/Consent/99");
        tefcaIas = JsonSerializer.Deserialize<TEFCAIASAuthorizationExtension>(tefcaIas.SerializeToJson());
        tefcaIas.ConsentPolicy?.Any().Should().BeFalse();

        tefcaIas.IalVetted.Value.GetRawText().Should().BeEquivalentTo(identityTokenElement.GetRawText()
            .Replace("\n", "").Replace("\r", "").Replace(": ", ":").Replace(",  ", ","));

        tefcaIas.IdToken.Value.GetRawText().Should().BeEquivalentTo(identityTokenElement.GetRawText()
            .Replace("\n", "").Replace("\r", "").Replace(": ", ":").Replace(",  ", ","));

        var realtedPersonResourceResult = new FhirJsonParser().Parse<RelatedPerson>(tefcaIas.UserInformation.Value.GetRawText());
        var patientResourceResult = new FhirJsonParser().Parse<RelatedPerson>(tefcaIas.PatientInformation.Value.GetRawText());


        realtedPersonResourceResult.Should().BeEquivalentTo(relatedPersonResource);
        patientResourceResult.Should().BeEquivalentTo(patientResource);
    }

    [Fact]
    public void DeserializeTestWhenRemovingItemFromList()
    {
        var builder = UdapDcrBuilderForClientCredentials
            .Create();

        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization/99").OriginalString;
        var organizationName = "FhirLabs";

        var hl7b2b = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName
        };

        hl7b2b.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        hl7b2b.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7b2b.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, hl7b2b);
        var document = builder.Build();

        var serializeDocument = document.SerializeToJson(true);
        _testOutputHelper.WriteLine(serializeDocument);

        document = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        var b2BAuthExtension = document?.Extensions?["hl7-b2b"] as HL7B2BAuthorizationExtension;
        b2BAuthExtension?.PurposeOfUse.Should().Contain("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2BAuthExtension?.ConsentPolicy.Should().Contain("https://udaped.fhirlabs.net/Policy/Consent/99");
        b2BAuthExtension?.ConsentReference.Should().Contain("https://fhirlabs.net/fhir/r4/Consent/99");
    }

    [Fact]
    public void Hl7b2bExtensionTest()
    {
        var builder = UdapDcrBuilderForClientCredentials
            .Create();

        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization/99").OriginalString;
        var organizationName = "FhirLabs";
        var purposeOfUse = new List<string>
        {
            "urn:oid:2.16.840.1.113883.5.8#TREAT"
        };
        var consentReference = new HashSet<string>
        {
            "https://fhirlabs.net/fhir/r4/Consent/99",
            "https://fhirlabs.net/fhir/r4/Consent|199"
        };
        var consentPolicy = new HashSet<string>
        {
            "https://udaped.fhirlabs.net/Policy/Consent/99",
            "https://udaped.fhirlabs.net/Policy/Consent|199"
        };

        var userPersonJson = File.ReadAllText("Model/Person-FASTIDUDAPPerson-Example.json");
        var parser = new FhirJsonParser();
        var personResource = parser.Parse<Person>(userPersonJson);
        personResource.Should().NotBeNull();
        var serializer = new FhirJsonSerializer();
        var userPerson = serializer.SerializeToString(personResource);
        userPerson.Should().NotBeNullOrEmpty();
        // _testOutputHelper.WriteLine(userPerson);

        var hl7b2b = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName,
            PurposeOfUse = purposeOfUse,
            ConsentReference = consentReference,
            ConsentPolicy = consentPolicy, // client supplied
        };
        

        JsonElement userPersonElement;
        using (var jasonDocument = JsonDocument.Parse(userPerson))
        {
            userPersonElement = jasonDocument.RootElement.Clone();
        }

        var b2bUserHl7 = new HL7B2BUserAuthorizationExtension()
        {
            UserPerson = userPersonElement,
            PurposeOfUse = purposeOfUse,
            ConsentReference = consentReference,
            ConsentPolicy = consentPolicy, // client supplied
        };

        // need to serialize to compare.
        var hl7b2bSerialized = hl7b2b.SerializeToJson();
        var hl7b2bUserSerialized = b2bUserHl7.SerializeToJson();

        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, hl7b2b);
        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER, b2bUserHl7);
        
        var document = builder.Build();

        // _testOutputHelper.WriteLine(document.SerializeToJson(true));

        var extensions = document.Extensions;

        extensions.Should().NotBeNull();
        extensions!.Count.Should().Be(2);
       

        var serializeDocument = JsonSerializer.Serialize(document, new JsonSerializerOptions()
        {
            WriteIndented = true
        });

        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        extensions = documentDeserialize?.Extensions;

        extensions.Should().NotBeNull();
        extensions!.Count.Should().Be(2);
        ((HL7B2BAuthorizationExtension)extensions["hl7-b2b"]).SerializeToJson().Should().BeEquivalentTo(hl7b2bSerialized);

        
        // _testOutputHelper.WriteLine(hl7b2bUserSerialized);
        // _testOutputHelper.WriteLine(((HL7B2BUserAuthorizationExtension)extentions["hl7-b2b-user"]).SerializeToJson(true));
        


        ((HL7B2BUserAuthorizationExtension)extensions["hl7-b2b-user"]).SerializeToJson().Should().BeEquivalentTo(hl7b2bUserSerialized);

        var extensionSerialized = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(((HL7B2BAuthorizationExtension)extensions["hl7-b2b"]).SerializeToJson());
        extensionSerialized!.Version.Should().Be("1");
        extensionSerialized.SubjectId.Should().Be(subjectId);
        extensionSerialized.SubjectName.Should().Be(subjectName);
        extensionSerialized.SubjectRole.Should().Be(subjectRole);
        extensionSerialized.OrganizationId.Should().Be(organizationId);
        extensionSerialized.OrganizationName.Should().Be(organizationName);
        extensionSerialized.ConsentReference.Should().ContainInOrder(consentReference);
        extensionSerialized.PurposeOfUse.Should().ContainInOrder(purposeOfUse);
        extensionSerialized.ConsentPolicy.Should().ContainInOrder(consentPolicy);

        hl7b2b = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId
        };

        builder = UdapDcrBuilderForClientCredentials.Create();
        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, hl7b2b);
        document = builder.Build();
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        extensionSerialized = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(((HL7B2BAuthorizationExtension)documentDeserialize!.Extensions!["hl7-b2b"]).SerializeToJson());
        extensionSerialized!.SubjectName.Should().BeNull();
        extensionSerialized.ConsentReference.Should().BeEmpty();

    }

    [Fact]
    public void Hl7b2bExtensionValidationTest()
    {
        var hl7b2b = new HL7B2BAuthorizationExtension()
        {
            Version = null
        };

        var notes = hl7b2b.Validate();
        notes.Should().NotBeNull();
        notes.Count().Should().Be(3);
        notes.Should().ContainInOrder("Missing required version", "Missing required organization_id", "Missing required purpose_of_use");
    }

    [Fact]
    public void Hl7b2bUserExtensionValidationTest()
    {
        var hl7b2b = new HL7B2BUserAuthorizationExtension()
        {
            Version = null
        };

        var notes = hl7b2b.Validate();
        notes.Should().NotBeNull();
        notes.Count().Should().Be(3);
        notes.Should().ContainInOrder("Missing required version", "Missing required user_person", "Missing required purpose_of_use");
    }

    [Fact]
    public void TefcaIASExtensionValidationTest()
    {
        var hl7b2b = new TEFCAIASAuthorizationExtension()
        {
            Version = null,
            PurposeOfUse = "Bad"
        };

        var notes = hl7b2b.Validate();
        notes.Should().NotBeNull();
        notes.Count().Should().Be(4);
        notes.Should().ContainInOrder("Missing required version", "Missing required user_information", "Missing required patient_information", "purpose_of_use must be T-IAS");
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
