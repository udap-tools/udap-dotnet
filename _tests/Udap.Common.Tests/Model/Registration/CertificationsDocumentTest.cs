#region (c) 2024-2025 Joseph Shook. All rights reserved;
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Udap.Model.Registration;
using Xunit.Abstractions;

namespace Udap.Common.Tests.Model.Registration
{
    public class CertificationsDocumentTest
    {
        private static readonly JsonSerializerOptions IndentedJsonOptions = new JsonSerializerOptions { WriteIndented = true };
        private readonly ITestOutputHelper _testOutputHelper;

        public CertificationsDocumentTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void UdapCertificationAndEndorsementDocument_SerializationTest()
        {
            var document = new UdapCertificationAndEndorsementDocument("Test Certification")
            {
                Issuer = "joe",
                Subject = "joe"
            };

            _testOutputHelper.WriteLine(JsonSerializer.Serialize(document, IndentedJsonOptions));
        }

        [Fact]
        public void CertificateTest()
        {
            //
            // Certificate required
            //
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification")
                .WithExpiration(DateTime.Now.AddDays(1));

            var ex = Assert.Throws<Exception>(act);
            Assert.StartsWith("Certificate required", ex.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification")
                .BuildSoftwareStatement();


            ex = Assert.Throws<Exception>(act);
            Assert.StartsWith("Missing certificate", ex.Message);
        }

        [Fact]
        public void CertificationExpirationTests()
        {
#if NET9_0_OR_GREATER
            var certificationCert =
                X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var certificationCert =
                new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif
            var expiration = certificationCert.NotAfter; // remember cannot be greater than 3 years

            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
            .WithExpiration(expiration.AddDays(1));

            var ex1 = Assert.Throws<ArgumentOutOfRangeException>(act);
            Assert.Equal("expirationOffset", ex1.ParamName);
            Assert.StartsWith("Expiration must not expire after certificate", ex1.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(DateTime.Now.AddYears(3));

            var ex2 = Assert.Throws<ArgumentOutOfRangeException>(act);
            Assert.Equal("expirationOffset", ex2.ParamName);
            Assert.StartsWith("Expiration limit to 3 years", ex2.Message);

            //
            // Still good on the actual expiration DateTime
            //
            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration);

            var exception = Record.Exception(act);
            Assert.Null(exception);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration + TimeSpan.FromSeconds(1));

            var ex3 = Assert.Throws<ArgumentOutOfRangeException>(act);
            Assert.Equal("expirationOffset", ex3.ParamName);
            Assert.StartsWith("Expiration must not expire after certificate", ex3.Message);



            //
            // User supplies Epoch time
            //
            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(new DateTimeOffset(expiration.AddDays(1)).ToUnixTimeSeconds());

            var ex4 = Assert.Throws<ArgumentOutOfRangeException>(act);
            Assert.Equal("expirationOffset", ex4.ParamName);
            Assert.StartsWith("Expiration must not expire after certificate", ex4.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(new DateTimeOffset(expiration).ToUnixTimeSeconds());

            exception = Record.Exception(act);
            Assert.Null(exception);
        }

        [Fact]
        public void LogoTests()
        {
            //
            // logo_uri
            //

            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLogoUri("Poof");

            var ex = Assert.Throws<UriFormatException>(act);
            Assert.Equal("Invalid URI: The format of the URI could not be determined.", ex.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png");

            var exception = Record.Exception(act);
            Assert.Null(exception);

            //
            // certification_logo
            //
            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithCertificationLogo("Poof");

            ex = Assert.Throws<UriFormatException>(act);
            Assert.Equal("Invalid URI: The format of the URI could not be determined.", ex.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithCertificationLogo("https://certifications.fhirlabs.net/logo.png");

            exception = Record.Exception(act);
            Assert.Null(exception);

            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name");
        }

        [Fact]
        public void LaunchUriTests()
        {
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLaunchUri("Poof");

            var ex = Assert.Throws<UriFormatException>(act);
            Assert.Equal("Invalid URI: The format of the URI could not be determined.", ex.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLaunchUri("https://smart.fhirlabs.net/launch");

            var exception = Record.Exception(act);
            Assert.Null(exception);
        }

        [Fact]
        public void AudienceTests()
        {
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithAudience("Poof");

            var ex = Assert.Throws<UriFormatException>(act);
            Assert.Equal("Invalid URI: The format of the URI could not be determined.", ex.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLaunchUri("https://securedcontrols.net/connect/register");

            var exception = Record.Exception(act);
            Assert.Null(exception);
        }

        /// <summary>
        /// It is not typical to set the iat claim yourself.  It is exposed to facilitate tooling that wants to
        /// test servers for how they handle an invalid iat claims.
        /// </summary>
        [Fact]
        public void IssuedAtTests()
        {
            var now = new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds();
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithIssuedAt(now)
                .Build();

            Assert.Equal(now, certificationsDoc.IssuedAt);

        }

        [Fact]
        public void JwtIdTests()
        {
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .Build();

            var firstJwtId = certificationsDoc.JwtId;
            Assert.False(string.IsNullOrWhiteSpace(certificationsDoc.JwtId));

            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .Build();

            Assert.NotEqual(firstJwtId, certificationsDoc.JwtId);

            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithJwtId("Joe-JwtId-1")
                .Build();

            Assert.Equal("Joe-JwtId-1", certificationsDoc.JwtId);
        }

        [Fact]
        public void CertificationDescriptionTests()
        {
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .Build();

            Assert.Null(certificationsDoc.CertificationDescription);

            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithCertificationDescription("Sample Description")
                .Build();

            Assert.Equal("Sample Description", certificationsDoc.CertificationDescription);

        }

        [Fact]
        public void CertificationStatusEndpointTests()
        {
            //
            // logo_uri
            //

            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .WithCertificationStatusEndpoint("Poof");

            var ex = Assert.Throws<UriFormatException>(act);
            Assert.Equal("Invalid URI: The format of the URI could not be determined.", ex.Message);

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .WithCertificationStatusEndpoint("https://certification.securedcontrols.net/status/AdminFhirLabsCertification");

            var exception = Record.Exception(act);
            Assert.Null(exception);
        }

        [Fact]
        public void EndorsementTests()
        {
            //
            // logo_uri
            //

           var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .Build();

           Assert.False(certificationsDoc.IsEndorsement);

           certificationsDoc = UdapCertificationsAndEndorsementBuilder
               .Create("AdminFhirLabsCertification")
               .WithEndorsement(true)
               .Build();

           Assert.True(certificationsDoc.IsEndorsement);
        }

        [Fact]
        public void JwksTests()
        {
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .WithJwks("Poof");

            Assert.Throws<NotImplementedException>(act);
        }

        [Fact]
        public void BuildCertification()
        {
#if NET9_0_OR_GREATER
            var certificationCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var certificationCert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif
            var expiration = certificationCert.NotAfter; // remember cannot be greater than 3 years
            
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration)
                .WithCertificationDescription("Application can perform all CRUD operations against the FHIR server.")
                .WithCertificationUris(new List<string>(){ "https://certifications.fhirlabs.net/criteria/admin-2024.7" })
                .WithDeveloperName("Joe Shook")
                .WithDeveloperAddress("Portland Oregon")
                .WithClientName("Udap.Common.Tests")
                .WithSoftwareId("XUnit.Test")
                .WithSoftwareVersion("0.3.0")
                .WithClientUri("https://certifications.fhirlabs.net")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png")
                .WithTermsOfService("https://certifications.fhirlabs.net")
                .WithPolicyUri("https://certifications.fhirlabs.net")
                .WithContacts(new List<string>(){ "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" })
                // SMART
                //.WithLaunchUri("https://udaped.fhirlabs.net/smart/launch?iss=https://launch.smarthealthit.org/v/r4/fhir&launch=WzAsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCJhdXRoX2ludmFsaWRfY2xpZW50X2lkIiwiIiwiIiwyLDFd")
                .WithRedirectUris(new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri })
                .WithIPsAllowed(new List<string>(){ "198.51.100.0/24", "203.0.113.55" })
                .WithGrantTypes(new List<string>(){"authorization_code", "refresh_token", "client_credentials"})
                .WithResponseTypes(new HashSet<string> { "code" }) // omit for client_credentials rule
                .WithScope("user/*.write")
                .WithTokenEndpointAuthMethod("private_key_jwt")  // 'none' if authorization server allows it.
                                                                 // 'client_secret_post': The client uses the HTTP POST parameters
                                                                 // as defined in OAuth 2.0, Section 2.3.1.
                                                                 // "client_secret_basic": The client uses HTTP Basic as defined in
                                                                 // OAuth 2.0, Section 2.3.1.
                                                                 //
                                                                 // The additional value private_key_jwt may also be used.
                                                                 //
                .Build();

            Assert.Null(certificationsDoc.Audience);


            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithAudience("https://securedcontrols.net/connect/register")
                .WithExpiration(expiration)
                .WithCertificationDescription("Application can perform all CRUD operations against the FHIR server.")
                .WithCertificationUris(new List<string>() { "https://certifications.fhirlabs.net/criteria/admin-2024.7" })
                .WithDeveloperName("Joe Shook")
                .WithDeveloperAddress("Portland Oregon")
                .WithClientName("Udap.Common.Tests")
                .WithSoftwareId("XUnit.Test")
                .WithSoftwareVersion("0.3.0")
                .WithClientUri("https://certifications.fhirlabs.net")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png")
                .WithTermsOfService("https://certifications.fhirlabs.net")
                .WithPolicyUri("https://certifications.fhirlabs.net")
                .WithContacts(new List<string>() { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" })
                // SMART
                //.WithLaunchUri("https://udaped.fhirlabs.net/smart/launch?iss=https://launch.smarthealthit.org/v/r4/fhir&launch=WzAsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCJhdXRoX2ludmFsaWRfY2xpZW50X2lkIiwiIiwiIiwyLDFd")
                .WithRedirectUris(new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri })
                .WithIPsAllowed(new List<string>() { "198.51.100.0/24", "203.0.113.55" })
                .WithGrantTypes(new List<string>() { "authorization_code", "refresh_token", "client_credentials" })
                .WithResponseTypes(new HashSet<string> { "code" }) // omit for client_credentials rule
                .WithScope("user/*.write")
                .WithTokenEndpointAuthMethod("private_key_jwt")  // 'none' if authorization server allows it.
                                                                 // 'client_secret_post': The client uses the HTTP POST parameters
                                                                 // as defined in OAuth 2.0, Section 2.3.1.
                                                                 // "client_secret_basic": The client uses HTTP Basic as defined in
                                                                 // OAuth 2.0, Section 2.3.1.
                                                                 //
                                                                 // The additional value private_key_jwt may also be used.
                                                                 //
                .Build();

            Assert.Equal("https://securedcontrols.net/connect/register", certificationsDoc.Audience);
            Assert.Equal("FhirLabs Administrator Certification", certificationsDoc.CertificationName);
            Assert.Equal(new DateTimeOffset(expiration).ToUnixTimeSeconds(), certificationsDoc.Expiration);
            
        }

        [Fact]
        public void BuildSotwareStatementForCertification()
        {
#if NET9_0_OR_GREATER
            var certificationCert =
                X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var certificationCert =
                new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif
            var expiration = certificationCert.NotAfter; // remember cannot be greater than 3 years

            var signedSoftwareStatement = UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration)
                .WithCertificationDescription("Application can perform all CRUD operations against the FHIR server.")
                .WithCertificationUris(new List<string>()
                    { "https://certifications.fhirlabs.net/criteria/admin-2024.7" })
                .WithDeveloperName("Joe Shook")
                .WithDeveloperAddress("Portland Oregon")
                .WithClientName("Udap.Common.Tests")
                .WithSoftwareId("XUnit.Test")
                .WithSoftwareVersion("0.3.0")
                .WithClientUri("https://certifications.fhirlabs.net")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png")
                .WithTermsOfService("https://certifications.fhirlabs.net")
                .WithPolicyUri("https://certifications.fhirlabs.net")
                .WithContacts(new List<string>() { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" })
                // SMART
                //.WithLaunchUri("https://udaped.fhirlabs.net/smart/launch?iss=https://launch.smarthealthit.org/v/r4/fhir&launch=WzAsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCJhdXRoX2ludmFsaWRfY2xpZW50X2lkIiwiIiwiIiwyLDFd")
                .WithRedirectUris(new List<string>
                    { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri })
                .WithIPsAllowed(new List<string>() { "198.51.100.0/24", "203.0.113.55" })
                .WithGrantTypes(new List<string>() { "authorization_code", "refresh_token", "client_credentials" })
                .WithResponseTypes(new HashSet<string> { "code" }) // omit for client_credentials rule
                .WithScope("user/*.write")
                .WithTokenEndpointAuthMethod("private_key_jwt") // 'none' if authorization server allows it.
                // 'client_secret_post': The client uses the HTTP POST parameters
                // as defined in OAuth 2.0, Section 2.3.1.
                // "client_secret_basic": The client uses HTTP Basic as defined in
                // OAuth 2.0, Section 2.3.1.
                //
                // The additional value private_key_jwt may also be used.
                //
                .BuildSoftwareStatement();
        }

        [Fact]
        public void ClampedExpiration_DefaultsToFiveMinutes()
        {
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif
            var before = DateTime.UtcNow.AddMinutes(5).AddSeconds(-5);
            var after = DateTime.UtcNow.AddMinutes(5).AddSeconds(5);

            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.Zero, cert);

            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            Assert.True(expDt > before);
            Assert.True(expDt < after);
            Assert.True(expDt <= cert.NotAfter.ToUniversalTime());
        }

        [Fact]
        public void ClampedExpiration_NegativeOffset_Throws()
        {
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif

            Action act = () => UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.FromSeconds(-1), cert);
            var ex = Assert.Throws<ArgumentOutOfRangeException>(act);
            Assert.Equal("expirationOffset", ex.ParamName);
        }

        [Fact]
        public void ClampedExpiration_ExceedsThreeYearPolicy_Clamped()
        {
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif

            var requested = TimeSpan.FromDays(365 * 5); // 5 years
            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(requested, cert);

            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            var maxPolicy = DateTime.UtcNow.AddYears(3).AddSeconds(10); // allow small timing drift
            Assert.True(expDt < maxPolicy);
        }

        [Fact]
        public void ClampedExpiration_ExceedsCertificate_NotAfterSafetyApplied()
        {
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif
            var safetySeconds = 7;
            var huge = TimeSpan.FromDays(2000);

            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(huge, cert, safetySeconds);

            var expected = cert.NotAfter.ToUniversalTime().AddSeconds(-safetySeconds);
            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;

            Assert.True((expected - expDt).Duration() < TimeSpan.FromSeconds(2));
        }

        [Fact]
        public void ClampedExpiration_CertificateTooShort_Throws()
        {
            //
            // This must create a certificate whose NotAfter is within (<=) safetySeconds of now
            // so that certLimit = NotAfter - safetySeconds is <= now and the method throws.
            //
            using var rsa = RSA.Create(2048);
            var now = DateTimeOffset.UtcNow;
            var req = new CertificateRequest("CN=ShortLived", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // NotBefore slightly in past, NotAfter only 4 seconds in the future.
            // Default safetySeconds = 5  => certLimit = (now + 4s) - 5s = now - 1s  => triggers the throw condition.
            var veryShortCert = req.CreateSelfSigned(now.AddSeconds(-30), now.AddSeconds(4));

            Action act = () => UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.Zero, veryShortCert);
            var ex = Assert.Throws<ArgumentOutOfRangeException>(act);
            Assert.Equal("certificate", ex.ParamName);
        }

        [Fact]
        public void ClampedExpiration_CertificateSoonButNotTooSoon_IsClampedNotThrown()
        {
            //
            // Certificate that expires soon (e.g. 90 seconds) but still outside safety window.
            // Should clamp (not throw) and set exp to NotAfter - safetySeconds.
            //
            using var rsa = RSA.Create(2048);
            var now = DateTimeOffset.UtcNow;
            var req = new CertificateRequest("CN=ShortButValid", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var shortButValidCert = req.CreateSelfSigned(now.AddSeconds(-10), now.AddSeconds(90)); // ~90s lifetime remaining

            var safetySeconds = 5;
            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.Zero, shortButValidCert, safetySeconds);

            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            var expected = shortButValidCert.NotAfter.ToUniversalTime().AddSeconds(-safetySeconds);

            // Allow tiny drift
            Assert.True((expected - expDt).Duration() < TimeSpan.FromSeconds(2));
        }

        [Fact]
        public void AdditionalClaims_SurviveSerializationRoundTrip()
        {
            var document = new UdapCertificationAndEndorsementDocument("TEFCA Basic App Certification")
            {
                Issuer = "urn:oid:2.999#T-TRTMNT",
                Subject = "urn:oid:2.999#T-TRTMNT",
                Scope = "user/*.read",
                AdditionalClaims = new Dictionary<string, JsonElement>
                {
                    ["exchange_purposes"] = JsonSerializer.SerializeToElement(
                        new[] { "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-IAS" }),
                    ["home_community_id"] = JsonSerializer.SerializeToElement("urn:oid:2.999")
                }
            };

            var json = document.SerializeToJson();
            _testOutputHelper.WriteLine(json);

            // Verify additional claims are in the serialized JSON
            var parsed = JsonDocument.Parse(json);
            Assert.True(parsed.RootElement.TryGetProperty("exchange_purposes", out var ep));
            Assert.Equal(JsonValueKind.Array, ep.ValueKind);
            Assert.Equal("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-IAS", ep[0].GetString());

            Assert.True(parsed.RootElement.TryGetProperty("home_community_id", out var hc));
            Assert.Equal("urn:oid:2.999", hc.GetString());

            // Deserialize back and verify additional claims survive
            var deserialized = JsonSerializer.Deserialize<UdapCertificationAndEndorsementDocument>(json);
            Assert.NotNull(deserialized);
            Assert.Equal("TEFCA Basic App Certification", deserialized!.CertificationName);
            Assert.Equal("user/*.read", deserialized.Scope);
            Assert.NotNull(deserialized.AdditionalClaims);
            Assert.True(deserialized.AdditionalClaims!.ContainsKey("exchange_purposes"));
            Assert.True(deserialized.AdditionalClaims.ContainsKey("home_community_id"));

            // Re-serialize and verify claims are still present
            var reJson = deserialized.SerializeToJson();
            var reParsed = JsonDocument.Parse(reJson);
            Assert.True(reParsed.RootElement.TryGetProperty("exchange_purposes", out _));
            Assert.True(reParsed.RootElement.TryGetProperty("home_community_id", out _));
        }

        [Fact]
        public void AdditionalClaims_IncludedInSignedSoftwareStatement()
        {
#if NET9_0_OR_GREATER
            var certificationCert =
                X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#else
            var certificationCert =
                new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
#endif

            var signedJwt = UdapCertificationsAndEndorsementBuilder
                .Create("TEFCA Basic App Certification", certificationCert)
                .WithClampedExpiration(TimeSpan.FromMinutes(5))
                .WithCertificationDescription("TEFCA Basic App Certification")
                .WithCertificationUris(new List<string>
                    { "https://rce.sequoiaproject.org/udap/profiles/basic-app-certification" })
                .WithScope("user/*.read")
                .WithTokenEndpointAuthMethod("private_key_jwt")
                .WithAdditionalClaims(new Dictionary<string, JsonElement>
                {
                    ["exchange_purposes"] = JsonSerializer.SerializeToElement(
                        new[] { "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-IAS" }),
                    ["home_community_id"] = JsonSerializer.SerializeToElement(
                        "2.16.840.1.113883.3.2054.2.4")
                })
                .BuildSoftwareStatement();

            Assert.NotNull(signedJwt);

            // Decode payload and verify additional claims are present
            var parts = signedJwt.Split('.');
            Assert.Equal(3, parts.Length);

            var payloadJson = Base64UrlEncoder.Decode(parts[1]);
            _testOutputHelper.WriteLine(payloadJson);

            var payload = JsonDocument.Parse(payloadJson);
            Assert.True(payload.RootElement.TryGetProperty("exchange_purposes", out var ep));
            Assert.Equal("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-IAS", ep[0].GetString());
            Assert.True(payload.RootElement.TryGetProperty("home_community_id", out var hc));
            Assert.Equal("2.16.840.1.113883.3.2054.2.4", hc.GetString());
        }
    }

    //
    // Register with only client_credentials C&E and then fail when a toke is requested for authorization_code.
    // Even if the standard registration contained authorization_code.  This
    //

    //
    // Important quote: the OAuth Server can also use the information in the certifications to inform the end user about the client.
    // From https://www.udap.org/udap-certifications-and-endorsements.html
    //


}