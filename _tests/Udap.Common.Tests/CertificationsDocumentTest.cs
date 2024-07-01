#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions.Common;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Xunit.Abstractions;


namespace Udap.Common.Tests
{
    public class CertificationsDocumentTest
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public CertificationsDocumentTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void UdapCertificationAndEndorsementDocument_SerializationTest()
        {
            var document = new UdapCertificationAndEndorsementDocument("Test Certification");
            document.Issuer = "joe";
            document.Subject = "joe";

            _testOutputHelper.WriteLine(JsonSerializer.Serialize(document,
                new JsonSerializerOptions
                {
                    WriteIndented = true
                    , DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                }));
        }

        [Fact(Skip = "not ready")]
        public void BuildCertification()
        {
            var certificationCert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
            
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Test Certification", certificationCert)
                .WithExpiration(certificationCert.NotAfter)
                .Build();
        }
    }
}