#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Common.Tests.Model.Access;

public class AccessTokenTests
{
    /// <summary>
    /// Without builder
    /// </summary>
    [Fact]
    public void TestHl7B2BExtensionSerialization()
    {
        var expiration = TimeSpan.FromMinutes(5);
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

        // act like we registered
        document.ClientId = Guid.NewGuid().ToString();

        //
        // hl7-b2b
        //
        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization/99").OriginalString;
        var organizationName = "FhirLabs";

        var b2BHl7 = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName
        };

        b2BHl7.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2BHl7.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.9#TREATX");
        b2BHl7.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        b2BHl7.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        b2BHl7.PurposeOfUse?.Remove("urn:oid:2.16.840.1.113883.5.9#TREATX");

        //
        // hl7-b2b-user
        //
        var userPersonJson = File.ReadAllText("Model/Person-FASTIDUDAPPerson-Example.json");
        var parser = new FhirJsonParser();
        var personResource = parser.Parse<Person>(userPersonJson);
        Assert.NotNull(personResource);
        var serializer = new FhirJsonSerializer();
        var userPerson = serializer.SerializeToString(personResource);
        Assert.False(string.IsNullOrEmpty(userPerson));
        // _testOutputHelper.WriteLine(userPerson);
        

        JsonElement userPersonElement;
        using (var jasonDocument = JsonDocument.Parse(userPerson))
        {
            userPersonElement = jasonDocument.RootElement.Clone();
        }

        // _testOutputHelper.WriteLine(userPersonElement.GetProperty("text").GetRawText());

        
        var b2BHl7User = new HL7B2BUserAuthorizationExtension()
        {
            UserPerson = userPersonElement,
        };
        

        b2BHl7User.PurposeOfUse?.Add("1.3.6.1.2.1.1.3.0#UPTIME");
        b2BHl7User.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/199");
        b2BHl7User.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/199");

        
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                document.ClientId,
                "https://server/connect/token",
                clientCert)
            .WithScope("system/Patient.rs")
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2BHl7)
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER, b2BHl7User)
            .Build("RS384");


        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(clientRequest.ClientAssertion.Value);
        var payload = jwtToken.Payload;
        var payloadJson = payload.SerializeToJson();

         //_testOutputHelper.WriteLine(payloadJson);

        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#TREAT", payloadJson);
        Assert.DoesNotContain("urn:oid:2.16.840.1.113883.5.9#TREATX", payloadJson);
        Assert.Contains("https://udaped.fhirlabs.net/Policy/Consent/99", payloadJson);
        Assert.Contains("https://fhirlabs.net/fhir/r4/Consent/99", payloadJson);


        Assert.Contains("1.3.6.1.2.1.1.3.0#UPTIME", payloadJson);
        Assert.Contains("https://udaped.fhirlabs.net/Policy/Consent/199", payloadJson);
        Assert.Contains("https://fhirlabs.net/fhir/r4/Consent/199", payloadJson);


        var extensions = PayloadSerializer.Deserialize((JsonElement)payload["extensions"]);
        var b2BUserResult =
            extensions[UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER] as HL7B2BUserAuthorizationExtension;
        Assert.NotNull(b2BUserResult!.UserPerson);
        var roundtrippedPerson = new FhirJsonParser().Parse<Person>(b2BUserResult.UserPerson!.Value.GetRawText());
        Assert.Equal(userPerson, new FhirJsonSerializer().SerializeToString(roundtrippedPerson));


        Assert.True(b2BHl7.PurposeOfUse!.Remove("urn:oid:2.16.840.1.113883.5.8#TREAT"));
        Assert.Empty(b2BHl7.PurposeOfUse);

        b2BHl7 = JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(b2BHl7.SerializeToJson());
        Assert.Empty(b2BHl7!.PurposeOfUse!);
    }

    [Fact]
    public void ClientCredentials_WithCertificateChain_IncludesMultipleX5cEntries()
    {
        var certPath = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(certPath, "udap-test");
#else
        var clientCert = new X509Certificate2(certPath, "udap-test");
#endif

        var intermediatePath = Path.Combine(AppContext.BaseDirectory, "CertStore/intermediates", "SureFhirLabs_Intermediate.cer");
#if NET9_0_OR_GREATER
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile(intermediatePath);
#else
        var intermediateCert = new X509Certificate2(intermediatePath);
#endif

        var certificates = new List<X509Certificate2> { clientCert, intermediateCert };

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                "test-client-id",
                "https://server/connect/token",
                certificates)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        Assert.NotNull(clientRequest.ClientAssertion.Value);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(clientRequest.ClientAssertion.Value);

        // Verify x5c header contains two certificates
        Assert.True(jwtToken.Header.ContainsKey("x5c"));
        var x5cArray = jwtToken.Header["x5c"] as List<object>;
        Assert.NotNull(x5cArray);
        Assert.Equal(2, x5cArray.Count);
    }

    [Fact]
    public void AuthorizationCode_WithCertificateChain_IncludesMultipleX5cEntries()
    {
        var certPath = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(certPath, "udap-test");
#else
        var clientCert = new X509Certificate2(certPath, "udap-test");
#endif

        var intermediatePath = Path.Combine(AppContext.BaseDirectory, "CertStore/intermediates", "SureFhirLabs_Intermediate.cer");
#if NET9_0_OR_GREATER
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile(intermediatePath);
#else
        var intermediateCert = new X509Certificate2(intermediatePath);
#endif

        var certificates = new List<X509Certificate2> { clientCert, intermediateCert };

        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
                "test-client-id",
                "https://server/connect/token",
                certificates,
                "https://client/callback",
                "test-auth-code")
            .Build("RS384");

        Assert.NotNull(tokenRequest.ClientAssertion.Value);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(tokenRequest.ClientAssertion.Value);

        // Verify x5c header contains two certificates
        Assert.True(jwtToken.Header.ContainsKey("x5c"));
        var x5cArray = jwtToken.Header["x5c"] as List<object>;
        Assert.NotNull(x5cArray);
        Assert.Equal(2, x5cArray.Count);
    }

    [Fact]
    public void ClientCredentials_SingleCert_StillWorks()
    {
        var certPath = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(certPath, "udap-test");
#else
        var clientCert = new X509Certificate2(certPath, "udap-test");
#endif

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                "test-client-id",
                "https://server/connect/token",
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        Assert.NotNull(clientRequest.ClientAssertion.Value);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(clientRequest.ClientAssertion.Value);

        Assert.True(jwtToken.Header.ContainsKey("x5c"));
        var x5cArray = jwtToken.Header["x5c"] as List<object>;
        Assert.NotNull(x5cArray);
        Assert.Single(x5cArray);
    }

    [Fact]
    public void AuthorizationCode_SingleCert_StillWorks()
    {
        var certPath = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile(certPath, "udap-test");
#else
        var clientCert = new X509Certificate2(certPath, "udap-test");
#endif

        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
                "test-client-id",
                "https://server/connect/token",
                clientCert,
                "https://client/callback",
                "test-auth-code")
            .Build("RS384");

        Assert.NotNull(tokenRequest.ClientAssertion.Value);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(tokenRequest.ClientAssertion.Value);

        Assert.True(jwtToken.Header.ContainsKey("x5c"));
        var x5cArray = jwtToken.Header["x5c"] as List<object>;
        Assert.NotNull(x5cArray);
        Assert.Single(x5cArray);
    }
}
