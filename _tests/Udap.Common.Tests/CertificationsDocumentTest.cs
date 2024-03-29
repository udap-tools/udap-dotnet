#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Udap.Model.Registration;
using Xunit.Abstractions;
using Task = System.Threading.Tasks.Task;

using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using IdentityModel;
using Claim = System.Security.Claims.Claim;
using System.Reflection.Emit;


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
            UdapCertificationAndEndorsementDocument document = new UdapCertificationAndEndorsementDocument("Test Certification");
            document.Issuer = "joe";
            document.Subject = "joe";

            _testOutputHelper.WriteLine(document.SerializeToJson());
        }

        [Fact]
        public async Task TestParametersResource()
        {
            var parametersJson = "{\"resourceType\":\"Parameters\",\"parameter\":[{\"name\":\"UdapEdPatientMatch\",\"resource\":{\"resourceType\":\"Patient\",\"birthDate\":\"1970-05-01\"}}]}";
            var parametersResource = await new FhirJsonParser().ParseAsync<Parameters>(parametersJson);

            _testOutputHelper.WriteLine(new FhirJsonSerializer().SerializeToString(parametersResource.Parameter.Single(n => n.Name == "UdapEdPatientMatch").Resource));

            var patient = parametersResource.Parameter.Single(n => n.Name == "UdapEdPatientMatch").Resource as Patient;
            Assert.Equal("1970-05-01", patient.BirthDate);

            var patientJson = await new FhirJsonSerializer().SerializeToStringAsync(parametersResource.Parameter
                .Single(n => n.Name == "UdapEdPatientMatch").Resource);
            patient = await new FhirJsonParser().ParseAsync<Patient>(patientJson);
            Assert.Equal("1970-05-01", patient.BirthDate);

            _testOutputHelper.WriteLine(await new FhirJsonSerializer(new SerializerSettings { Pretty = true }).SerializeToStringAsync(parametersResource));
        }


        [Fact(Skip = "Experimental")]
        public void TestJOeWindows()
        {
            // The secret key used to sign the JWT
            string secretKey = "my_secret_key";

            // Convert the secret key to a byte array
            byte[] keyBytes = Encoding.UTF8.GetBytes(secretKey);

            // Load the private key from a file or other source
            var cert = new X509Certificate2(@"C:\Source\GitHub\JoeShook\udap-tools\udap-dotnet\_tests\Udap.PKI.Generator\certstores\localhost_fhirlabs_community6\issued\fhirLabsApiClientLocalhostCert6_ECDSA.pfx", "udap-test", X509KeyStorageFlags.Exportable);



            AsymmetricAlgorithm key = cert.GetECDsaPrivateKey();

            byte[] encryptedPrivKeyBytes = key.ExportEncryptedPkcs8PrivateKey(
                "udap-test",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            ecdsa.ImportEncryptedPkcs8PrivateKey("udap-test".AsSpan(), encryptedPrivKeyBytes.AsSpan(), out int bytesRead);
            //var key = ecdsa.ExportECPrivateKey();

            // Console.WriteLine(privateKeyBytes.Length);
            // // Convert the private key to the appropriate format
            // // byte[] formattedPrivateKeyBytes = ConvertPrivateKeyToPkcs8(privateKeyBytes);
            //
            // // Create the ECDsa instance with the appropriate curve
            // ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            //
            // // Import the key into the ECDsa instance
            // ecdsa.ImportECPrivateKey(privateKeyBytes, out _);

            // Create the signing credentials using the ECDsa instance and algorithm
            var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha384);

            // var securityKey = new X509SecurityKey(cert);
            // var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha384);
            //
            // Create the JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, "John Doe"),
                    new Claim(ClaimTypes.Email, "john.doe@example.com")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = signingCredentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            _testOutputHelper.WriteLine(jwt);
        }

        [Fact(Skip = "Experimental")]
        public void TestJOe()
        {
            // The secret key used to sign the JWT
            string secretKey = "my_secret_key";

            // Convert the secret key to a byte array
            byte[] keyBytes = Encoding.UTF8.GetBytes(secretKey);

            // Load the private key from a file or other source
            var cert = new X509Certificate2(@"C:\Source\GitHub\JoeShook\udap-tools\udap-dotnet\_tests\Udap.PKI.Generator\certstores\localhost_fhirlabs_community6\issued\fhirLabsApiClientLocalhostCert6_ECDSA.pfx");
            //var cert = new X509Certificate2(@"/mnt/c/Source/GitHub/JoeShook/udap-tools/udap-dotnet/_tests/Udap.PKI.Generator/certstores/localhost_fhirlabs_community6/issued/fhirLabsApiClientLocalhostCert6_ECDSA.pfx", "udap-test", X509KeyStorageFlags.Exportable);
            var joe = cert.HasPrivateKey;
            byte[] privateKeyBytes = cert.GetECDsaPrivateKey().ExportECPrivateKey(); //Might be DER encoded
            // Console.WriteLine(privateKeyBytes.Length);
            // // Convert the private key to the appropriate format
            // // byte[] formattedPrivateKeyBytes = ConvertPrivateKeyToPkcs8(privateKeyBytes);
            //
            // // Create the ECDsa instance with the appropriate curve
            // ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            //
            // // Import the key into the ECDsa instance
            // ecdsa.ImportECPrivateKey(privateKeyBytes, out _);

            // Create the signing credentials using the ECDsa instance and algorithm
            //var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha384);

            var securityKey = new X509SecurityKey(cert);
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha384);

            // Create the JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, "John Doe"),
                    new Claim(ClaimTypes.Email, "john.doe@example.com")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = signingCredentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            Console.WriteLine(jwt);
        }


        /// <summary>
        /// Still would need to put the kid in the jwt header segment
        /// But a good experiment to mess with while working in ECDSA certificates.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task ExperimentGenECDSAPublishJwksSignThenValidateMultipleTimes()
        {
            using RSA key = RSA.Create(2048);
            _testOutputHelper.WriteLine(key.ExportRSAPublicKeyPem());

            var securityKey = new RsaSecurityKey(key.ExportParameters(true));
            var rsaSigningCredentials = new SigningCredentials(securityKey, "RS256");

            var rsaTokenHandler = new JwtSecurityTokenHandler();
            var rsaTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, "Hobo Joe"),
                    new Claim(ClaimTypes.Email, "hobo.joe@example.com"),
                    new Claim("jti", CryptoRandom.CreateUniqueId()),
                    // Should be no longer than 5 minutes in the future
                    new (JwtClaimTypes.Expiration,
                        EpochTime.GetIntDate(DateTime.Now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = rsaSigningCredentials,
                Issuer = "MyClientId",
                Audience = "https://fhirlabs.net/fhir/r4"
            };
            
            var rsaToken = rsaTokenHandler.CreateToken(rsaTokenDescriptor);
            var rsaJwt = rsaTokenHandler.WriteToken(rsaToken);
            _testOutputHelper.WriteLine("");
            _testOutputHelper.WriteLine(rsaJwt);




            string jwt = string.Empty;

            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

            _testOutputHelper.WriteLine(ecdsa.ExportSubjectPublicKeyInfoPem());
            _testOutputHelper.WriteLine(ecdsa.ExportECPrivateKeyPem());

            var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));
            _testOutputHelper.WriteLine(JsonSerializer.Serialize(jwk,
                new JsonSerializerOptions { WriteIndented = true }));

            var jwks = new Jwks()
            {
                Kid = jwk.Kid ?? "MyKid",
                Kty = jwk.Kty,
                Crv = jwk.Crv, 
                X = jwk.X, 
                Y = jwk.Y
            };

            //
            // Generated public JWKS
            //
            _testOutputHelper.WriteLine(JsonSerializer.Serialize(jwks,
                new JsonSerializerOptions { WriteIndented = true }));


            var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), "ES384");
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                        new Claim(ClaimTypes.Name, "Hobo Joe"),
                        new Claim(ClaimTypes.Email, "hobo.joe@example.com"),
                        new Claim("jti", CryptoRandom.CreateUniqueId()),
                        // Should be no longer than 5 minutes in the future
                        new (JwtClaimTypes.Expiration,
                            EpochTime.GetIntDate(DateTime.Now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = signingCredentials,
                Issuer = "MyClientId",
                Audience = "https://fhirlabs.net/fhir/r4"
            };

            //
            // Signing
            //

            var token = tokenHandler.CreateToken(tokenDescriptor);
            jwt = tokenHandler.WriteToken(token);
            _testOutputHelper.WriteLine(jwt);


            //
            // Validate Signed JWT
            //
            var restResult = jwks; //simulate rest get to jwks
            var validateHandler = new JwtSecurityTokenHandler();

            using (var ecdsaValidate = ECDsa.Create(

                       new ECParameters()
                       {
                           Q = new ECPoint()
                           {
                               X = Base64UrlEncoder.DecodeBytes(restResult.X),
                               Y = Base64UrlEncoder.DecodeBytes(restResult.Y),
                           },
                           Curve = ECCurve.NamedCurves.nistP384
                       }
                   ))
            {

                var validatedToken = await validateHandler.ValidateTokenAsync(
                    jwt,
                    new TokenValidationParameters
                    {
                        RequireSignedTokens = true,
                        ValidateIssuer = true, // no issuer
                        ValidIssuers = new string[] { "MyClientId" },
                        ValidateIssuerSigningKey = true,
                        ValidateAudience = true, // No aud for UDAP metadata
                        ValidAudiences = new string[] { "https://fhirlabs.net/fhir/r4" },
                        ValidateLifetime = true,
                        IssuerSigningKey = new ECDsaSecurityKey(ecdsaValidate),
                        ValidAlgorithms = new[] { "ES384" }
                    });

                Assert.True(validatedToken.IsValid, validatedToken.Exception?.Message);
            }

            //
            // Negative test
            //
            using (var ecdsaValidate = ECDsa.Create(

                       new ECParameters()
                       {
                           Q = new ECPoint()
                           {
                               X = Base64UrlEncoder.DecodeBytes("B4f00ZyMUsvRnvkmn5fu0VVVoEI0Cxj9PzMJfzDb5zQomp5tRXDdzX3wTVsw_Rsu"),
                               Y = Base64UrlEncoder.DecodeBytes("ZKqTmJnMyADasE_WjamzJ4zPTA19b2wfVWsOKFWnu7TeTpfyYR3HhUhEvFSiprWZ"),
                           },
                           Curve = ECCurve.NamedCurves.nistP384
                       }
                   ))
            {
                var validatedToken = await validateHandler.ValidateTokenAsync(
                    jwt,
                    new TokenValidationParameters
                    {
                        RequireSignedTokens = true,
                        ValidateIssuer = true, // no issuer
                        ValidIssuers = new string[] { "MyClientId" },
                        ValidateIssuerSigningKey = true,
                        ValidateAudience = true, // No aud for UDAP metadata
                        ValidAudiences = new string[] { "https://fhirlabs.net/fhir/r4" },
                        ValidateLifetime = true,
                        IssuerSigningKey = new ECDsaSecurityKey(ecdsaValidate),
                        ValidAlgorithms = new[] { "ES384" }
                    });

                Assert.False(validatedToken.IsValid);

                _testOutputHelper.WriteLine(validatedToken.Exception?.Message);
            }
        }

        public class Jwks
        {
            [JsonPropertyName("kty")]
            public string Kty { get; set; }
            [JsonPropertyName("crv")]
            public string Crv { get; set; }
            [JsonPropertyName("x")]
            public string X { get; set; }
            [JsonPropertyName("y")]
            public string Y { get; set; }
            [JsonPropertyName("kid")]
            public string Kid { get; set; }
        }

        // Helper function to convert a private key to PKCS8 format
        public static byte[] ConvertPrivateKeyToPkcs8(byte[] privateKey)
        {
            using (var stream = new MemoryStream(privateKey))
            {
                using (var reader = new StreamReader(stream))
                {
                    var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                    var keyPair = pemReader.ReadObject() as Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair;
                    var pkcs8 = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded();
                    return pkcs8;
                }
            }
        }
    }
}