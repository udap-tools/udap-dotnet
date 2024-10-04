using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Firely.Fhir.Packages;
using Hl7.Fhir.Introspection;
using Hl7.Fhir.Model;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;
using Hl7.Fhir.Specification;
using Hl7.Fhir.Specification.Source;
using Hl7.Fhir.Specification.Terminology;
using Hl7.Fhir.Utility;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Xunit.Abstractions;
using Claim = System.Security.Claims.Claim;
using Task = System.Threading.Tasks.Task;
// ReSharper disable All
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

namespace Udap.Common.Tests;

public class ExperimentationTest
{
    private readonly ITestOutputHelper _testOutputHelper;

    public ExperimentationTest(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact(Skip = "Experimenting")]
    public async Task GetCodeSystem()
    {
        var settings = new FhirClientSettings
        {
            PreferredFormat = ResourceFormat.Json,
            VerifyFhirVersion = false
        };


        var fhirClient = new FhirClient("https://tx.fhir.org/r4/", settings);

        fhirClient.Settings.PreferredFormat = ResourceFormat.Json;
        var codeSystem = await fhirClient.ReadAsync<Hl7.Fhir.Model.CodeSystem>("https://tx.fhir.org/r4/CodeSystem/v2-0203");
        var codeSystemJson = await new FhirJsonSerializer().SerializeToStringAsync(codeSystem!);
    }

    [Fact(Skip = "Experimenting")]
    public async Task FhirTermTest()
    {
        IAsyncResourceResolver _resolver = new FhirPackageSource(ModelInfo.ModelInspector, @"C:\temp\IdentityMatchingIG\hl7.fhir.us.identity-matching-2.0.0-draft.tgz");
        var termService = new LocalTerminologyService(resolver: _resolver, new ValueSetExpanderSettings(){IncludeDesignations = true});
        var p = new ExpandParameters()
            .WithValueSet(url: "http://hl7.org/fhir/us/identity-matching/ValueSet/Identity-Identifier-vs");
                
        var joe = await termService.Expand(p);
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(joe, new JsonSerializerOptions(){WriteIndented = true}));
        _testOutputHelper.WriteLine("Goodbye Joe");
    }

    private const string PACKAGESERVER = "http://packages.simplifier.net";
    private const string IDENTITY_MATCHING = "hl7.fhir.us.identity-matching@1.0.0";

    [Fact(Skip = "Experimenting")]
    public async Task FhirTermExternalTest()
    {
        FhirPackageSource _clientResolver = new(new ModelInspector(FhirRelease.R4), PACKAGESERVER, new string[] { "hl7.fhir.r4.core@4.0.1", "hl7.fhir.r4.expansions@4.0.1", IDENTITY_MATCHING });
        var termService = new LocalTerminologyService(resolver: _clientResolver);
        var p = new ExpandParameters().WithValueSet(url: "http://hl7.org/fhir/us/identity-matching/ValueSet/Identity-Identifier-vs");
        var joe = await termService.Expand(p);
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(joe, new JsonSerializerOptions() { WriteIndented = true }));
        _testOutputHelper.WriteLine("Goodbye Joe");
    }

    public class InternalResolver : IAsyncResourceResolver
    {
        /// <summary>Find a resource based on its relative or absolute uri.</summary>
        /// <param name="uri">A resource uri.</param>
        public Task<Resource> ResolveByUriAsync(string uri)
        {
            throw new NotImplementedException();
        }

        /// <summary>Find a (conformance) resource based on its canonical uri.</summary>
        /// <param name="uri">The canonical url of a (conformance) resource.</param>
        public Task<Resource> ResolveByCanonicalUriAsync(string uri)
        {
            throw new NotImplementedException();
        }
    }

    public class InternalTerminologyService : ITerminologyService
    {
        private static readonly SemaphoreSlim _semaphore = new(1, 1);

        private readonly IAsyncResourceResolver _resolver;
        private readonly ValueSetExpander _expander;

        public InternalTerminologyService(IAsyncResourceResolver resolver, ValueSetExpanderSettings? expanderSettings = null)
        {
            _resolver = resolver ?? throw Error.ArgumentNull(nameof(resolver));

            var settings = expanderSettings ?? ValueSetExpanderSettings.CreateDefault();
            settings.ValueSetSource ??= resolver;

            _expander = new ValueSetExpander(settings);
        }

        ///<inheritdoc />
        public async Task<Resource> Expand(Parameters parameters, string? id = null, bool useGet = false)
        {
            var joe = await _resolver.FindValueSetAsync(id);
            return null!;
            // throw new NotImplementedException();
            // return await Endpoint.InstanceOperationAsync(constructUri<ValueSet>(id), RestOperation.EXPAND_VALUESET, parameters, useGet).ConfigureAwait(false);
        }

        ///<inheritdoc />
        public Task<Parameters> ValueSetValidateCode(Parameters parameters, string? id = null, bool useGet = false)
        {
            throw new NotImplementedException();
        }

        ///<inheritdoc />
        public Task<Parameters> Subsumes(Parameters parameters, string? id = null, bool useGet = false)
        {
            throw new NotImplementedException();
        }

        ///<inheritdoc />
        public Task<Parameters> CodeSystemValidateCode(Parameters parameters, string? id = null, bool useGet = false)
        {
            throw new NotImplementedException();
        }

        ///<inheritdoc />
        public Task<Parameters> Lookup(Parameters parameters, bool useGet = false)
        {
            throw new NotImplementedException();
        }

        ///<inheritdoc />
        public Task<Parameters> Translate(Parameters parameters, string? id = null, bool useGet = false)
        {
            throw new NotImplementedException();
        }

        ///<inheritdoc />
        public Task<Resource> Closure(Parameters parameters, bool useGet = false)
        {
            throw new NotImplementedException();
        }
    }

        

    [Fact]
    public async Task TestParametersResource()
    {
        var parametersJson = "{\"resourceType\":\"Parameters\",\"parameter\":[{\"name\":\"UdapEdPatientMatch\",\"resource\":{\"resourceType\":\"Patient\",\"birthDate\":\"1970-05-01\"}}]}";
        var parametersResource = await new FhirJsonParser().ParseAsync<Parameters>(parametersJson);

        _testOutputHelper.WriteLine(new FhirJsonSerializer().SerializeToString(parametersResource.Parameter.Single(n => n.Name == "UdapEdPatientMatch").Resource));

        var patient = parametersResource.Parameter.Single(n => n.Name == "UdapEdPatientMatch").Resource as Patient;
        Assert.Equal("1970-05-01", patient!.BirthDate);

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

        byte[] encryptedPrivKeyBytes = key!.ExportEncryptedPkcs8PrivateKey(
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
        byte[] privateKeyBytes = cert.GetECDsaPrivateKey()!.ExportECPrivateKey(); //Might be DER encoded
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

#if NET7_0_OR_GREATER
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
#endif

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
        using var stream = new MemoryStream(privateKey);
        using var reader = new StreamReader(stream);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var keyPair = pemReader.ReadObject() as Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair;
        var pkcs8 = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair!.Private).GetDerEncoded();
        return pkcs8;
    }
}