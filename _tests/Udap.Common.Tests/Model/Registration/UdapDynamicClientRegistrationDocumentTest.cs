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
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Tefca.Model;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using Claim = System.Security.Claims.Claim;
using JsonClaimValueTypes = Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes;

namespace Udap.Common.Tests.Model.Registration;
public class UdapDynamicClientRegistrationDocumentTest
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new JsonSerializerOptions { WriteIndented = true };
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
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

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

        document.AddClaims([new("MyClaim", "Testing 123", ClaimValueTypes.String)]);

        Assert.Null(document.ClientId);
        Assert.Equal("https://securedcontrols.net/connect/register", document.Audience);
        Assert.True(Math.Abs(document.Expiration.GetValueOrDefault() - expirationEpochTime) <= 3);
        Assert.False(string.IsNullOrWhiteSpace(document.JwtId));
        Assert.Equal("dotnet system test client", document.ClientName);
        Assert.Equal(2, document.Contacts!.Count);
        Assert.Contains("mailto:Joseph.Shook@Surescripts.com", document.Contacts);
        Assert.Contains("mailto:JoeShook@gmail.com", document.Contacts);
        Assert.Equal(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue, document.TokenEndpointAuthMethod);
        Assert.Equal("system/Patient.rs system/Practitioner.read", document.Scope);
        Assert.Equal("https://avatars.githubusercontent.com/u/77421324?s=48&v=4", document.LogoUri);
        Assert.Empty(document.ResponseTypes!);
        Assert.Single(document.GrantTypes!);
        Assert.Contains("client_credentials", document.GrantTypes);

        var iat = EpochTime.DateTime(document.IssuedAt.GetValueOrDefault()).ToUniversalTime();


        document.ClientId = "MyNewClientId"; // Simulate successful registration
        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        Assert.Equal(document.ClientId, documentDeserialize!.ClientId);
        Assert.NotEmpty(documentDeserialize);
        Assert.Equal(document.Audience, documentDeserialize.Audience);
        Assert.Equal(document.Expiration, documentDeserialize.Expiration);
        Assert.Equal(document.JwtId, documentDeserialize.JwtId);
        Assert.Equal(document.ClientName, documentDeserialize.ClientName);
        foreach (var contact in document.Contacts) { Assert.Contains(contact, documentDeserialize.Contacts!); }
        Assert.Equal(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue, documentDeserialize.TokenEndpointAuthMethod);
        Assert.Equal(document.Scope, documentDeserialize.Scope);
        Assert.Equal(document.LogoUri, documentDeserialize.LogoUri);
        Assert.Single(documentDeserialize.GrantTypes!);
        Assert.Equal(document.SoftwareStatement, documentDeserialize.SoftwareStatement); //echo back software statement
        Assert.Empty(documentDeserialize.ResponseTypes!);
        Assert.Equal("Testing 123", documentDeserialize["MyClaim"].ToString());
        Assert.Equal(EpochTime.GetIntDate(iat), documentDeserialize.IssuedAt);


        // Extra property coverage details
        document.Contacts = null;
        document.Extensions = null;
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        Assert.Empty(documentDeserialize!.Contacts!);
        Assert.Empty(documentDeserialize.Extensions!);

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

        var exception = Record.Exception(buildSoftwareStatement);
        Assert.Null(exception);


        Action buildSoftwareStatementRs384 = () => UdapDcrBuilderForClientCredentials
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

        exception = Record.Exception(buildSoftwareStatementRs384);
        Assert.Null(exception);

    }

    [Fact]
    public void CancelRegistrationClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

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

        Assert.Empty(document.GrantTypes!);
    }


    /// <summary>
    /// Pick another issuer that matches a SAN other than the first one in the Certificate
    /// </summary>
    [Fact]
    public void AlternateSanClientCredentialsTest()
    {
        EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
        .Build();

        Assert.Equal("https://fhirlabs.net:7016/fhir/r4", document.Issuer);

        Action act = () => UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/not_here"));

        var ex = Assert.Throws<Exception>(act);
        Assert.StartsWith("End certificate does not contain a URI Subject Alternative Name of, https://fhirlabs.net:7016/fhir/not_here", ex.Message);

    }

    [Fact]
    public void ControlTimesClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var issuedAt = EpochTime.GetIntDate(DateTime.Now);
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithExpiration(expiration)
            .WithIssuedAt(issuedAt)
            .Build();

        Assert.Equal(issuedAt, document.IssuedAt);
        Assert.Equal(expiration, document.Expiration);

    }

    [Fact]
    public void CertificateRequiredClientCredentials()
    {
        Action create = () => UdapDcrBuilderForClientCredentials
            .Create()
            .BuildSoftwareStatement();

        var ex = Assert.Throws<Exception>(create);
        Assert.StartsWith("Missing certificate", ex.Message);

        Action cancel = () => UdapDcrBuilderForClientCredentials
            .Cancel()
            .BuildSoftwareStatement();

        ex = Assert.Throws<Exception>(cancel);
        Assert.StartsWith("Missing certificate", ex.Message);
    }

    [Fact]
    public void ErrorClientCredentialsTest()
    {
        var document = UdapDcrBuilderForClientCredentials
            .Create()
            .Build();

        document.AddClaims(
        [
            new Claim("error", "Poof"),
            new Claim("error_description", "Poof description")
        ]);

        Assert.Equal("Poof", document.GetError());
        Assert.Equal("Poof description", document.GetErrorDescription());
    }

    [Fact]
    public void ClaimClientCredentialsTest()
    {
        var document = UdapDcrBuilderForClientCredentials
            .Create()
            .Build();

        // var now = DateTime.Now.ToOADate().ToString(); 

        document.AddClaims(
        [
            new Claim("bool", "true", ClaimValueTypes.Boolean),
            new Claim("string", "hello", ClaimValueTypes.String),
            new Claim("double", "10.5", ClaimValueTypes.Double),
            new Claim("null", "null", JsonClaimValueTypes.JsonNull),
            // new Claim("datetime", now, ClaimValueTypes.DateTime),
            new Claim("integer64", Int64.MaxValue.ToString(), ClaimValueTypes.Integer64),
            new Claim("json", "{\"joe\":\"test\"}", JsonClaimValueTypes.Json),
            new Claim("jsonarray", "[\"one\", \"two\"]", JsonClaimValueTypes.JsonArray)
        ]);

        Assert.Equal(true, document["bool"]);
        Assert.Equal("hello", document["string"]);
        Assert.Equal(10.5, document["double"]);
        Assert.Equal("", document["null"]);
        Assert.Equal(Int64.MaxValue, document["integer64"]);
        Assert.Equal("{\"joe\":\"test\"}", (document["json"] as JsonObject)?.ToJsonString());
        Assert.Equal("[\"one\",\"two\"]", (document["jsonarray"] as JsonArray)?.ToJsonString());
        // document["datetime"].Should().Be(now);
    }

    /// <summary>
    /// Without builder
    /// </summary>
    [Fact]
    public void TestHl7B2BExtensionSerialization()
    {
        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization/99").OriginalString;
        var organizationName = "FhirLabs";

        var hl7B2B = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName
        };

        hl7B2B.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        hl7B2B.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7B2B.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        var serializeDocument = hl7B2B.SerializeToJson();

        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#TREAT", serializeDocument);
        Assert.Contains("https://udaped.fhirlabs.net/Policy/Consent/99", serializeDocument);
        Assert.Contains("https://fhirlabs.net/fhir/r4/Consent/99", serializeDocument);


        Assert.True(hl7B2B.PurposeOfUse?.Remove("urn:oid:2.16.840.1.113883.5.8#TREAT"));
        Assert.Empty(hl7B2B.PurposeOfUse!);

        hl7B2B = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(hl7B2B.SerializeToJson());
        Assert.Equal(0, hl7B2B?.PurposeOfUse!.Count);
    }

    /// <summary>
    /// Without builder
    /// </summary>
    [Fact]
    public void TestHl7B2BUserExtensionSerialization()
    {
        var userPersonJson = File.ReadAllText("Model/Person-FASTIDUDAPPerson-Example.json");
        var parser = new FhirJsonParser();
        var personResource = parser.Parse<Person>(userPersonJson);
        Assert.NotNull(personResource);
        var serializer = new FhirJsonSerializer();
        var userPerson = serializer.SerializeToString(personResource);
        Assert.False(string.IsNullOrEmpty(userPerson));

        JsonElement userPersonElement;
        using (var jasonDocument = JsonDocument.Parse(userPerson))
        {
            userPersonElement = jasonDocument.RootElement.Clone();
        }

        var hl7B2BUser = new HL7B2BUserAuthorizationExtension()
        {
            UserPerson = userPersonElement,
        };

        hl7B2BUser.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        hl7B2BUser.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7B2BUser.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        var serializeDocument = hl7B2BUser.SerializeToJson();

        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#TREAT", serializeDocument);
        Assert.Contains("https://udaped.fhirlabs.net/Policy/Consent/99", serializeDocument);
        Assert.Contains("https://fhirlabs.net/fhir/r4/Consent/99", serializeDocument);

        hl7B2BUser = JsonSerializer.Deserialize<HL7B2BUserAuthorizationExtension>(serializeDocument);

        Assert.True(hl7B2BUser!.PurposeOfUse!.Remove("urn:oid:2.16.840.1.113883.5.8#TREAT"));
        Assert.Empty(hl7B2BUser.PurposeOfUse);

        hl7B2BUser.ConsentPolicy!.Remove("https://udaped.fhirlabs.net/Policy/Consent/99");
        Assert.Empty(hl7B2BUser.ConsentPolicy!);

        Assert.DoesNotContain("https://udaped.fhirlabs.net/Policy/Consent/99", hl7B2BUser.SerializeToJson());
        hl7B2BUser = JsonSerializer.Deserialize<HL7B2BUserAuthorizationExtension>(hl7B2BUser.SerializeToJson());
        Assert.Empty(hl7B2BUser?.ConsentPolicy!);
    }

    /// <summary>
    /// Without builder
    /// </summary>
    [Fact]
    public void TestTefcaIasExtensionSerialization()
    {
        var relatedPersonJson = File.ReadAllText("Model/RelatedPersonExample.json");
        var relatedPersonResource = new FhirJsonParser().Parse<RelatedPerson>(relatedPersonJson);
        Assert.NotNull(relatedPersonResource);
        var relatedPerson = new FhirJsonSerializer().SerializeToString(relatedPersonResource);
        Assert.False(string.IsNullOrEmpty(relatedPerson));

        JsonElement relatedPersonElement;
        using (var jasonDocument = JsonDocument.Parse(relatedPerson))
        {
            relatedPersonElement = jasonDocument.RootElement.Clone();
        }

        var patientJson = File.ReadAllText("Model/PatientExample.json");
        var patientResource = new FhirJsonParser().Parse<Patient>(patientJson);
        Assert.NotNull(relatedPersonResource);
        var patient = new FhirJsonSerializer().SerializeToString(patientResource);
        Assert.False(string.IsNullOrEmpty(patient));

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
            IdToken = identityTokenElement
        };

        tefcaIas.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        tefcaIas.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        Assert.Empty(tefcaIas.Validate());

        var serializeDocument = tefcaIas.SerializeToJson(true);

        // _testOutputHelper.WriteLine(serializeDocument);


        Assert.Contains("https://udaped.fhirlabs.net/Policy/Consent/99", serializeDocument);
        Assert.Contains("https://fhirlabs.net/fhir/r4/Consent/99", serializeDocument);

        tefcaIas = JsonSerializer.Deserialize<TEFCAIASAuthorizationExtension>(serializeDocument);

        tefcaIas!.ConsentPolicy!.Remove("https://udaped.fhirlabs.net/Policy/Consent/99");
        Assert.Empty(tefcaIas.ConsentPolicy);

        Assert.DoesNotContain("https://udaped.fhirlabs.net/Policy/Consent/99", tefcaIas.SerializeToJson());
        tefcaIas = JsonSerializer.Deserialize<TEFCAIASAuthorizationExtension>(tefcaIas.SerializeToJson());
        Assert.Empty(tefcaIas!.ConsentPolicy!);

        Assert.Equal(identityTokenElement.GetRawText()
            .Replace("\n", "").Replace("\r", "").Replace(": ", ":").Replace(",  ", ","),
            tefcaIas.IdToken?.GetRawText(), StringComparer.OrdinalIgnoreCase);

        var relatedPersonResourceResult = new FhirJsonParser().Parse<RelatedPerson>(tefcaIas.UserInformation?.GetRawText());
        var patientResourceResult = new FhirJsonParser().Parse<Patient>(tefcaIas.PatientInformation?.GetRawText());


        Assert.Equal(JsonSerializer.Serialize(relatedPersonResource), JsonSerializer.Serialize(relatedPersonResourceResult));
        Assert.Equal(JsonSerializer.Serialize(patientResource), JsonSerializer.Serialize(patientResourceResult));
    }

    /// <summary>
    /// This test proves that UdapDynamicClientRegistrationDocument can accomodate
    /// exp and iat that are passed as string claims rather than numbers.
    /// SerializeToJson() has the <see cref="UdapDynamicClientRegistrationDocumentConverter"/> applied
    /// to fixup the <see cref="UdapDynamicClientRegistrationDocument"/> model object.
    /// Remember that <see cref="UdapDynamicClientRegistrationDocument"/> inherits from Dictionary<string, object>
    /// allowing for any claim to be added, which is how claims like HL7-B2B and TEFCA-IAS are added.
    /// </summary>
    [Fact]
    public void DeserializeExtended()
    {
        var json = @"{
    ""client_id"": ""484e5844-5980-4b9d-8b3b-c48dfaaa0979"",
    ""software_statement"": ""..."",
    ""redirect_uris"": [],
    ""grant_types"": [
        ""client_credentials""
    ],
    ""response_types"": [],
    ""token_endpoint_auth_method"": ""private_key_jwt"",
    ""client_name"": ""FhirLabs UdapEd"",
    ""iss"": ""https://fhirlabs.net/fhir/r4"",
    ""sub"": ""https://fhirlabs.net/fhir/r4"",
    ""aud"": ""https://ihe-nimbus.epic.com/Interconnect-FHIR/udap/register"",
    ""exp"": ""1736962786"",
    ""iat"": ""1736962486"",
    ""jti"": ""jPC7DYv90QDuPbF2ik2BqyAie6B6Pblszo1ji3pB8oM"",
    ""contacts"": [
        ""mailto:Joseph.Shook@Surescripts.com"",
        ""mailto:JoeShook@gmail.com""
    ],
    ""scope"": ""..."",
    ""logo_uri"": """"
}";

        var udapRegistrationDocument = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(json);
        var serializedJson = udapRegistrationDocument!.SerializeToJson(true);
        Assert.Contains("1736962786", serializedJson);
        Assert.DoesNotContain("\"1736962786\"", serializedJson);
        // _testOutputHelper.WriteLine(serializedJson);
        
        udapRegistrationDocument = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(
            json,
            new JsonSerializerOptions()
            {
                Converters = {
                    new UdapDynamicClientRegistrationDocumentConverter(),
                }
            });

        Assert.Equal(1736962486, udapRegistrationDocument!.IssuedAt);
        Assert.Equal(1736962786, udapRegistrationDocument.Expiration);
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

        var hl7B2BUser = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName
        };

        hl7B2BUser.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        hl7B2BUser.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7B2BUser.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, hl7B2BUser);
        var document = builder.Build();

        var serializeDocument = document.SerializeToJson(true);
        // _testOutputHelper.WriteLine(serializeDocument);

        document = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        var b2BAuthExtension = document?.Extensions?["hl7-b2b"] as HL7B2BAuthorizationExtension;
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#TREAT", b2BAuthExtension?.PurposeOfUse!);
        Assert.Contains("https://udaped.fhirlabs.net/Policy/Consent/99", b2BAuthExtension?.ConsentPolicy!);
        Assert.Contains("https://fhirlabs.net/fhir/r4/Consent/99", b2BAuthExtension?.ConsentReference!);
    }

    [Fact]
    public void AddExtensionViaExtensionsProperty()
    {
        var builder = UdapDcrBuilderForClientCredentials
            .Create();

        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization/99").OriginalString;
        var organizationName = "FhirLabs";

        var hl7B2BUser = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName
        };

        hl7B2BUser.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        hl7B2BUser.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        hl7B2BUser.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        var document = builder.Build();
        document.Extensions = new Dictionary<string, object>
        {
            {UdapConstants.UdapAuthorizationExtensions.Hl7B2B, hl7B2BUser}
        };

        var serializeDocument = document.SerializeToJson(true);
        // _testOutputHelper.WriteLine(serializeDocument);

        document = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        var b2BAuthExtension = document?.Extensions?["hl7-b2b"] as HL7B2BAuthorizationExtension;
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#TREAT", b2BAuthExtension?.PurposeOfUse!);
        Assert.Contains("https://udaped.fhirlabs.net/Policy/Consent/99", b2BAuthExtension?.ConsentPolicy!);
        Assert.Contains("https://fhirlabs.net/fhir/r4/Consent/99", b2BAuthExtension?.ConsentReference!);
    }

    [Fact]
    public void Hl7B2BExtensionTest()
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
        Assert.NotNull(personResource);
        var serializer = new FhirJsonSerializer();
        var userPerson = serializer.SerializeToString(personResource);
        Assert.False(string.IsNullOrEmpty(userPerson));
        // _testOutputHelper.WriteLine(userPerson);

        var hl7B2BUser = new HL7B2BAuthorizationExtension()
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

        var b2BUserHl7 = new HL7B2BUserAuthorizationExtension()
        {
            UserPerson = userPersonElement,
            PurposeOfUse = purposeOfUse,
            ConsentReference = consentReference,
            ConsentPolicy = consentPolicy, // client supplied
        };

        // need to serialize to compare.
        var hl7B2BSerialized = hl7B2BUser.SerializeToJson();
        var hl7B2BUserSerialized = b2BUserHl7.SerializeToJson();

        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, hl7B2BUser);
        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER, b2BUserHl7);
        
        var document = builder.Build();

        // _testOutputHelper.WriteLine(document.SerializeToJson(true));

        var extensions = document.Extensions;

        Assert.NotNull(extensions);
        Assert.Equal(2, extensions!.Count);


        var serializeDocument = JsonSerializer.Serialize(document, IndentedJsonOptions);

        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        extensions = documentDeserialize?.Extensions;

        Assert.NotNull(extensions);
        Assert.Equal(2, extensions!.Count);
        Assert.Equal(hl7B2BSerialized, ((HL7B2BAuthorizationExtension)extensions["hl7-b2b"]).SerializeToJson(), StringComparer.OrdinalIgnoreCase);

        
        // _testOutputHelper.WriteLine(hl7B2BUserUserSerialized);
        // _testOutputHelper.WriteLine(((HL7B2BUserAuthorizationExtension)extentions["hl7-b2b-user"]).SerializeToJson(true));
        


        Assert.Equal(hl7B2BUserSerialized, ((HL7B2BUserAuthorizationExtension)extensions["hl7-b2b-user"]).SerializeToJson(), StringComparer.OrdinalIgnoreCase);

        var extensionSerialized = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(((HL7B2BAuthorizationExtension)extensions["hl7-b2b"]).SerializeToJson());
        Assert.Equal("1", extensionSerialized!.Version);
        Assert.Equal(subjectId, extensionSerialized.SubjectId);
        Assert.Equal(subjectName, extensionSerialized.SubjectName);
        Assert.Equal(subjectRole, extensionSerialized.SubjectRole);
        Assert.Equal(organizationId, extensionSerialized.OrganizationId);
        Assert.Equal(organizationName, extensionSerialized.OrganizationName);
        Assert.Equal(consentReference.ToList(), extensionSerialized.ConsentReference!.ToList());
        Assert.Equal(purposeOfUse, extensionSerialized.PurposeOfUse!.ToList());
        Assert.Equal(consentPolicy.ToList(), extensionSerialized.ConsentPolicy!.ToList());

        hl7B2BUser = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId
        };

        builder = UdapDcrBuilderForClientCredentials.Create();
        builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, hl7B2BUser);
        document = builder.Build();
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        extensionSerialized = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(((HL7B2BAuthorizationExtension)documentDeserialize!.Extensions!["hl7-b2b"]).SerializeToJson());
        Assert.Null(extensionSerialized!.SubjectName);
        Assert.Empty(extensionSerialized.ConsentReference!);

    }

    [Fact]
    public void Hl7B2BExtensionValidationTest()
    {
        var hl7B2BUser = new HL7B2BAuthorizationExtension()
        {
            Version = null!
        };

        var notes = hl7B2BUser.Validate();
        Assert.NotNull(notes);
        Assert.Equal(3, notes.Count);
        Assert.Equal(new List<string> { "Missing required version", "Missing required organization_id", "Missing required purpose_of_use" }, notes);
    }

    [Fact]
    public void Hl7B2BUserExtensionValidationTest()
    {
        var hl7B2BUser = new HL7B2BUserAuthorizationExtension()
        {
            Version = null!
        };

        var notes = hl7B2BUser.Validate();
        Assert.NotNull(notes);
        Assert.Equal(3, notes.Count);
        Assert.Equal(new List<string> { "Missing required version", "Missing required user_person", "Missing required purpose_of_use" }, notes);
    }

    [Fact]
    public void TefcaIasExtensionValidationTest()
    {
        var hl7B2BUser = new TEFCAIASAuthorizationExtension()
        {
            Version = null!
        };

        var notes = hl7B2BUser.Validate();
        Assert.NotNull(notes);
        Assert.Equal(3, notes.Count);
        Assert.Equal(new List<string> { "Missing required version", "Missing required user_information", "Missing required patient_information" }, notes);
    }

    [Fact]
    public void ClaimAuthorizationCodeFlowTest()
    {
        var document = UdapDcrBuilderForClientCredentials
            .Create()
            .Build();

        // var now = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"); 

        document.AddClaims(
        [
            new Claim("bool", "true", ClaimValueTypes.Boolean),
            new Claim("string", "hello", ClaimValueTypes.String),
            new Claim("double", "10.5", ClaimValueTypes.Double),
            new Claim("null", "null", JsonClaimValueTypes.JsonNull),
            // new Claim("datetime", now, ClaimValueTypes.DateTime),
        ]);

        Assert.Equal(true, document["bool"]);
        Assert.Equal("hello", document["string"]);
        Assert.Equal(10.5, document["double"]);
        Assert.Equal("", document["null"]);
        // document["datetime"].Should().Be(now);
    }

    [Fact]
    public void AuthorizationCodeFlowTest()
    {
        var expiration = TimeSpan.FromMinutes(5);
        var expirationEpochTime = EpochTime.GetIntDate(DateTime.Now.Add(expiration));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

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

        document.AddClaims([new Claim("MyClaim", "Testing 123")]);

        Assert.Null(document.ClientId);
        Assert.Equal("https://securedcontrols.net/connect/register", document.Audience);
        Assert.True(Math.Abs(document.Expiration.GetValueOrDefault() - expirationEpochTime) <= 3);
        Assert.False(string.IsNullOrWhiteSpace(document.JwtId));
        Assert.Equal("dotnet system test client", document.ClientName);
        Assert.Equal(2, document.Contacts!.Count);
        Assert.Contains("mailto:Joseph.Shook@Surescripts.com", document.Contacts);
        Assert.Contains("mailto:JoeShook@gmail.com", document.Contacts);
        Assert.Equal(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue, document.TokenEndpointAuthMethod);
        Assert.Equal("system/Patient.rs system/Practitioner.read", document.Scope);
        Assert.Contains("code", document.ResponseTypes!);
        Assert.Equal("https://fhirlabs.net/fhir/r4", document.Issuer); // same as first subject alternative name
        Assert.Single(document.RedirectUris!);
        Assert.Contains("https://client.fhirlabs.net/redirect/", document.RedirectUris);
        Assert.Equal("https://avatars.githubusercontent.com/u/77421324?s=48&v=4", document.LogoUri);
        Assert.Single(document.GrantTypes!);
        Assert.Contains("authorization_code", document.GrantTypes);

        var signedDocument = SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(clientCert, document).Build();

        document.SoftwareStatement = signedDocument;
        document.ClientId = "MyNewClientId"; // Simulate successful registration
        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        Assert.Equal(document.ClientId, documentDeserialize!.ClientId);
        Assert.NotEmpty(documentDeserialize);
        Assert.Equal(document.Audience, documentDeserialize.Audience);
        Assert.Equal(document.Expiration, documentDeserialize.Expiration);
        Assert.Equal(document.JwtId, documentDeserialize.JwtId);
        Assert.Equal(document.ClientName, documentDeserialize.ClientName);
        Assert.Equal(document.Contacts!.ToList(), documentDeserialize.Contacts!.ToList());
        Assert.Equal(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue, documentDeserialize.TokenEndpointAuthMethod);
        Assert.Equal(document.Scope, documentDeserialize.Scope);
        Assert.False(string.IsNullOrWhiteSpace(documentDeserialize.SoftwareStatement));
        Assert.Equal(document.SoftwareStatement, documentDeserialize.SoftwareStatement); //echo back software statement
        Assert.Equal(document.ResponseTypes!.ToList(), documentDeserialize.ResponseTypes!.ToList());
        Assert.Equal(document.Issuer, documentDeserialize.Issuer);
        Assert.Equal(document.RedirectUris!.ToList(), documentDeserialize.RedirectUris!.ToList());
        Assert.Equal(document.LogoUri, documentDeserialize.LogoUri);
        Assert.Single(documentDeserialize.GrantTypes!);
        foreach (var gt in document.GrantTypes!) { Assert.Contains(gt, documentDeserialize.GrantTypes); }
        Assert.Equal("Testing 123", documentDeserialize["MyClaim"].ToString());

        // Extra property coverage details
        document.Contacts = null;
        document.ResponseTypes = null;
        document.GrantTypes = null;
        document.RedirectUris = null;
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        Assert.Empty(documentDeserialize!.Contacts!);
        Assert.Empty(documentDeserialize.ResponseTypes!);
        Assert.Empty(documentDeserialize.GrantTypes!);
        Assert.Empty(documentDeserialize.RedirectUris!);

        // What might happen on responding from Server
        var _ = new UdapDynamicClientRegistrationDocument()
        {
            ClientId = document.ClientId,
            SoftwareStatement = document.SoftwareStatement
        };


        // ReSharper disable once ObjectCreationAsStatement
#pragma warning disable CA1806
        Action act = () => new UdapDynamicClientRegistrationDocument()
#pragma warning restore CA1806
        {
            ClientId = document.ClientId,
            SoftwareStatement = null
        };

        var exception = Record.Exception(act);
        Assert.Null(exception);


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

        exception = Record.Exception(buildSoftwareStatement);
        Assert.Null(exception);

        Action buildSoftwareStatementRs384 = () => UdapDcrBuilderForAuthorizationCode
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

        exception = Record.Exception(buildSoftwareStatementRs384);
        Assert.Null(exception);
    }

    /// <summary>
    /// Test that the SignedSoftwareStatementBuilder can add multiple x5c certificates to the header
    /// </summary>
    [Fact]
    public void SignedSoftwareStatementBuilderTestForMultipleX5cInHeader()
    {
        var expiration = TimeSpan.FromMinutes(5);
        var endCertPath = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var intermediateCertPath = Path.Combine(AppContext.BaseDirectory, "CertStore/intermediates", "SureFhirLabs_Intermediate.cer");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(endCertPath, "udap-test");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile(intermediateCertPath);
#else
        var clientCert = new X509Certificate2(endCertPath, "udap-test");
        var intermediateCert = new X509Certificate2(intermediateCertPath);
#endif
        var chain = new List<X509Certificate2> { clientCert, intermediateCert };

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

        var signedDocument = SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(chain, document).Build();

        document.SoftwareStatement = signedDocument;
        document.ClientId = "MyNewClientId"; // Simulate successful registration
        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);


        var tokenHandler = new JsonWebTokenHandler();
        var jsonWebToken = tokenHandler.ReadJsonWebToken(documentDeserialize!.SoftwareStatement);


        var certificates = jsonWebToken.GetCertificateList();
        Assert.NotNull(certificates);
        Assert.Equal(2, certificates!.Count);
        Assert.Equal(clientCert.Thumbprint, certificates.First().Thumbprint);
        Assert.Equal(intermediateCert.Thumbprint, certificates.Last().Thumbprint);
    }

    /// <summary>
    /// Test that the UdapDcrBuilderForClientCredentials can add multiple x5c certificates to the header
    /// </summary>
    [Fact]
    public void UdapDcrBuilderForClientCredentials_TestForMultipleX5cInHeader()
    {
        var endCertPath = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var intermediateCertPath = Path.Combine(AppContext.BaseDirectory, "CertStore/intermediates", "SureFhirLabs_Intermediate.cer");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(endCertPath, "udap-test");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile(intermediateCertPath);
#else
        var clientCert = new X509Certificate2(endCertPath, "udap-test");
        var intermediateCert = new X509Certificate2(intermediateCertPath);
#endif
        var chain = new List<X509Certificate2> { clientCert, intermediateCert };

        var softwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(chain)
            .BuildSoftwareStatement();

        var tokenHandler = new JsonWebTokenHandler();
        var jsonWebToken = tokenHandler.ReadJsonWebToken(softwareStatement);
        var certificates = jsonWebToken.GetCertificateList();
        Assert.NotNull(certificates);
        Assert.Equal(2, certificates!.Count);
        Assert.Equal(clientCert.Thumbprint, certificates.First().Thumbprint);
        Assert.Equal(intermediateCert.Thumbprint, certificates.Last().Thumbprint);
    }

    /// <summary>
    /// Test that the UdapDcrBuilderForAuthorizationCode can add multiple x5c certificates to the header
    /// </summary>
    [Fact]
    public void UdapDcrBuilderForAuthorizationCode_TestForMultipleX5cInHeader()
    {
        var endCertPath = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var intermediateCertPath = Path.Combine(AppContext.BaseDirectory, "CertStore/intermediates", "SureFhirLabs_Intermediate.cer");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(endCertPath, "udap-test");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile(intermediateCertPath);
#else
        var clientCert = new X509Certificate2(endCertPath, "udap-test");
        var intermediateCert = new X509Certificate2(intermediateCertPath);
#endif
        var chain = new List<X509Certificate2> { clientCert, intermediateCert };

        var softwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(chain)
            .BuildSoftwareStatement();

        var tokenHandler = new JsonWebTokenHandler();
        var jsonWebToken = tokenHandler.ReadJsonWebToken(softwareStatement);
        var certificates = jsonWebToken.GetCertificateList();
        Assert.NotNull(certificates);
        Assert.Equal(2, certificates!.Count);
        Assert.Equal(clientCert.Thumbprint, certificates.First().Thumbprint);
        Assert.Equal(intermediateCert.Thumbprint, certificates.Last().Thumbprint);
    }

    /// <summary>
    /// Pick another issuer that matches a SAN other than the first one in the Certificate
    /// </summary>
    [Fact]
    public void AlternateSanAuthorizationCodeFlowTest()
    {
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .Build();

        Assert.Equal("https://fhirlabs.net:7016/fhir/r4", document.Issuer);

        Action act = () => UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/not_here"));

        var ex = Assert.Throws<Exception>(act);
        Assert.StartsWith("End certificate does not contain a URI Subject Alternative Name of, https://fhirlabs.net:7016/fhir/not_here", ex.Message);
    }

    [Fact]
    public void CancelRegistrationAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

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

        Assert.Empty(document.GrantTypes!);
    }

    [Fact]
    public void ControlTimesAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var issuedAt = EpochTime.GetIntDate(DateTime.Now);
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithExpiration(expiration)
            .WithIssuedAt(issuedAt)
            .Build();

        Assert.Equal(issuedAt, document.IssuedAt);
        Assert.Equal(expiration, document.Expiration);

    }
    [Fact]
    public void AuthorizationCodeFlowSetResponseTypeTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
        var clientCert = new X509Certificate2(cert, "udap-test");
#endif

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

        Assert.Equal(new HashSet<string> { "code", "secret" }.ToList(), documentAuthCode.ResponseTypes!.ToList());
    }

    [Fact]
    public void CertificateRequiredAuthorizationCodeTest()
    {
        Action create = () => UdapDcrBuilderForAuthorizationCode
            .Create()
            .BuildSoftwareStatement();

        var ex = Assert.Throws<Exception>(create);
        Assert.StartsWith("Missing certificate", ex.Message);

        Action cancel = () => UdapDcrBuilderForAuthorizationCode
            .Cancel()
            .BuildSoftwareStatement();

        ex = Assert.Throws<Exception>(cancel);
        Assert.StartsWith("Missing certificate", ex.Message);
    }

    [Fact]
    public void ErrorAuthorizationCodeFlowTest()
    {
        var document = UdapDcrBuilderForAuthorizationCode
            .Create()
            .Build();

        document.AddClaims(
        [
            new Claim("error", "Poof"),
            new Claim("error_description", "Poof description")
        ]);

        Assert.Equal("Poof", document.GetError());
        Assert.Equal("Poof description", document.GetErrorDescription());
    }
}
