#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IdentityModel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Xunit.Abstractions;
using program = FhirLabsApi.Program;


namespace WebApi.Community.Tests.FhirLabsApi;

public class ApiForCommunityTestFixture : WebApplicationFactory<program>
{
    public ITestOutputHelper? Output { get; set; }
    private UdapMetadata? _wellKnownUdap;
    public string Community = "http://localhost";

    public UdapMetadata? WellKnownUdap
    {
        get
        {
            if (_wellKnownUdap == null)
            {
                var response = CreateClient()
                    .GetAsync($"fhir/r4/.well-known/udap?community={Community}")
                    .GetAwaiter()
                    .GetResult();

                response.StatusCode.Should().Be(HttpStatusCode.OK);
                var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                _wellKnownUdap = JsonConvert.DeserializeObject<UdapMetadata>(content, new JsonSerializerSettings
                {
                    ContractResolver = new DefaultContractResolver
                    {
                        NamingStrategy = new SnakeCaseNamingStrategy()
                    }
                });
            }

            return _wellKnownUdap;
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        //
        // Linux needs to know how to find appsettings file in web api under test.
        // Still works with Windows but what a pain.  This feels fragile
        // TODO: 
        //
        builder.UseSetting("contentRoot", "../../../../../examples/FhirLabsApi");
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(Output!);
        });

        return base.CreateHost(builder);
    }
}


public class UdapControllerCommunityTest : IClassFixture<ApiForCommunityTestFixture>
{
    private readonly ApiForCommunityTestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly FakeChainValidatorDiagnostics _diagnosticsChainValidator = new FakeChainValidatorDiagnostics();

    public UdapControllerCommunityTest(ApiForCommunityTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        if (fixture == null) throw new ArgumentNullException(nameof(fixture));
        fixture.Output = testOutputHelper;
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;
    }

    [Fact] //Swagger
    public async Task OpenApiTest()
    {
        var response = await _fixture.CreateClient().GetAsync($"fhir/r4/Swagger/Index.html");

        System.Diagnostics.Trace.WriteLine(response.ToString());

        response.StatusCode.Should().Be(HttpStatusCode.OK, "Should be status ok");
        var contentType = response.Content.Headers.ContentType;
        contentType.Should().NotBeNull(); 
        contentType!.MediaType.Should().Be("text/html", "Should be status ok");

        var result = await response.Content.ReadAsStringAsync();
        result
            .Should()
            .Contain(
                "./swagger-ui.css",
                "Does not seem to be the standard swagger ui html");

        //
        // TODO
        // This last part doesn't actually catch failures.  I would need to render the html 
        // some how to finish the test.
        // To make this fail just change one of the helper methods in udapController from
        // private to public.


        result
            .Should()
            .NotContain(
                "Failed to load API definition",
                "Swagger UI Failed to load.");
    }

    [Fact]
    public void signed_metatdataContentTest()
    {
        var jwt = new JwtSecurityToken(_fixture.WellKnownUdap?.SignedMetadata);
        var tokenHeader = jwt.Header;
        var x5CArray = JsonConvert.DeserializeObject<string[]>(tokenHeader.X5c);

        // bad keys
        // var x5cArray = new string[1];
        // x5cArray[0] = "MIIFVzCCAz+gAwIBAgIEAQIDBDANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJVUzEPMA0GA1UECBMGT3JlZ29uMREwDwYDVQQHEwhQb3J0bGFuZDEUMBIGA1UEChMLSG9ibyBDb2RpbmcxDzANBgNVBAsTBkFuY2hvcjEZMBcGA1UEAxMQVURBUC1UZXN0LUFuY2hvcjAeFw0yMjA4MzEyMDI4NDBaFw0yNDA5MDEyMDI4NDBaMG8xCzAJBgNVBAYTAlVTMQ8wDQYDVQQIEwZPcmVnb24xETAPBgNVBAcTCFBvcnRsYW5kMRQwEgYDVQQKEwtIb2JvIENvZGluZzENMAsGA1UECxMEVURBUDEXMBUGA1UEAxMOd2VhdGhlcmFwaS5sYWIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkU61gOhliibnE2L2SMX4bNE/WqVxpgdRyW2Ii7kbdW5f/eATAhWjrm1koKrCiR9/fH6hK/HEYPBgT/QKU6fTEgBjJEf51ouGHEZzYkEldKMZCjZnxCYRYbF+PhflhnLyj0R0NagH2OFzrrKj3qwPZ3WDSUDC/kxh7YNWJGnOo33bhD+gh+SYdq598cJiXsyfL1N9iTstXYKCKwmP+iJNQ5dV14dbDm693XlVe/G3JwADNzxRoIRVe9Yb9KcE7o7BIy18jUjJySfrAa3Y3Z9jX5ng89CVI3HHiQ9fVHrZjkYUaqe+0c88Asg3op3HPQNyk6bjKxgU7tHfZm5O+KyM9AgMBAAGjgfYwgfMwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwHQYDVR0OBBYEFGYofTfZyODDCPMoMV7QaUpVGNKHMB8GA1UdIwQYMBaAFEKu+NexBjBGKrtMYo6DzwUKs4tJMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jZXJ0cy53ZWF0aGVyYXBpLmxhYi9jcmwvY3JsX2xpc3QuY3JsMCsGA1UdEQQkMCKGIGh0dHBzOi8vd2VhdGhlcmFwaS5sYWI6NTAyMS9maGlyMCoGA1UdJQEB/wQgMB4GCCsGAQUFBwMCBggrBgEFBQcDAQYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADaTQff7z0BZNgoKDkjxzZNKfUsHfWIsuOe8zfAfYzXAqUiyBWl8pdrL7EW9JoKLchQPC5grWW8uUfzknD3El0QGLgXNvm+imsk0NXaH0R9vEIafJhGXkZWIZx61GekoUQ8+7xEbf9gr5BGA3jMWAtkO6+LvZuhdkTd1k2RlVpl39Yx56Ivg/KpgRXM1PyISl1obbC/b5PCQ/t4kysTmkU9GVz1Z7+rUPcCP+fKFblsLLToVgxA13ozYRAF9/k2V9n/ZiHSOJmwPwLwBs9yHwsdefBlQ9G0Rzm9oU89G5o74HNlhInqD4wQspm+uhewwIAzRkGfL+t992nn1il8rt+VnnZ97rMIZ+cCjyvB0JmlsRQlngRt9cJbHp0OAo5jD8WJwbwgJ0Z3qClCvxZVwT9H5c+klre31ef61XrC0foPkX3TBSytnWh2iQkAdME6ChKl2RZKac2V4zCG8JgSRcP85lDooigsnBk5Sqmf3cifxm29Fte4X/0JG1IpSCLFLcaLyj2me0mVUNDnzIalLaBwwY4kNLPEppJhlFUUV16efaHwOesSQJvGk77tCGaGsG3kPUQcOa0tb2lYJho0Jnq6xymcNZuUQ5PLXmq6l7/gGJ7AqCb1fDghF0PlTwOkh+ZFiaja1YxzN9SsqsR9hyAUJt0mpzqzLNXjWa3PAcy+P";

        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()));
        var tokenHandler = new JwtSecurityTokenHandler();

        tokenHandler.ValidateToken(_fixture.WellKnownUdap?.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            //With ValidateIssuer = true issuer is validated against this list.
            //Docs are not clear on this, thus this example.
            ValidIssuers = new[] { "http://localhost/fhir/r4" }, 
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = new[] { tokenHeader.Alg }, //must match signing algorithm

        }, out SecurityToken valdatedToken);


        var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
        issClaim.ValueType.Should().Be(ClaimValueTypes.String);

        // should be the same as the web base url, but this would be localhost
        issClaim.Value.Should().Be("http://localhost/fhir/r4");
        
        var subjectAltName = cert.GetNameInfo(X509NameType.UrlName, false);
        subjectAltName.Should().Be(issClaim.Value,
            $"iss: {issClaim.Value} does not match Subject Alternative Name extension");

        var subClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Subject);
        subClaim.ValueType.Should().Be(ClaimValueTypes.String);

        issClaim.Value.Should().BeEquivalentTo(subClaim.Value);

        var iatClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.IssuedAt);
        iatClaim.ValueType.Should().Be(ClaimValueTypes.Integer);

        var expClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Expiration);
        expClaim.ValueType.Should().Be(ClaimValueTypes.Integer);

        var iat = int.Parse(iatClaim.Value);
        var exp = int.Parse(expClaim.Value);
        var year = DateTimeOffset.FromUnixTimeSeconds(exp).AddYears(1).ToUnixTimeSeconds();
        iat.Should().BeLessOrEqualTo((int)year);
    }

    [Fact]
    public void ValidateChainTest()
    {
        var jwt = new JwtSecurityToken(_fixture.WellKnownUdap?.SignedMetadata);
        var tokenHeader = jwt.Header;

        var x5cArray = JsonConvert.DeserializeObject<string[]>(tokenHeader.X5c);

        // bad keys
        // var x5cArray = new string[1];
        // x5cArray[0] = "MIIFVzCCAz+gAwIBAgIEAQIDBDANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJVUzEPMA0GA1UECBMGT3JlZ29uMREwDwYDVQQHEwhQb3J0bGFuZDEUMBIGA1UEChMLSG9ibyBDb2RpbmcxDzANBgNVBAsTBkFuY2hvcjEZMBcGA1UEAxMQVURBUC1UZXN0LUFuY2hvcjAeFw0yMjA4MzEyMDI4NDBaFw0yNDA5MDEyMDI4NDBaMG8xCzAJBgNVBAYTAlVTMQ8wDQYDVQQIEwZPcmVnb24xETAPBgNVBAcTCFBvcnRsYW5kMRQwEgYDVQQKEwtIb2JvIENvZGluZzENMAsGA1UECxMEVURBUDEXMBUGA1UEAxMOd2VhdGhlcmFwaS5sYWIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkU61gOhliibnE2L2SMX4bNE/WqVxpgdRyW2Ii7kbdW5f/eATAhWjrm1koKrCiR9/fH6hK/HEYPBgT/QKU6fTEgBjJEf51ouGHEZzYkEldKMZCjZnxCYRYbF+PhflhnLyj0R0NagH2OFzrrKj3qwPZ3WDSUDC/kxh7YNWJGnOo33bhD+gh+SYdq598cJiXsyfL1N9iTstXYKCKwmP+iJNQ5dV14dbDm693XlVe/G3JwADNzxRoIRVe9Yb9KcE7o7BIy18jUjJySfrAa3Y3Z9jX5ng89CVI3HHiQ9fVHrZjkYUaqe+0c88Asg3op3HPQNyk6bjKxgU7tHfZm5O+KyM9AgMBAAGjgfYwgfMwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwHQYDVR0OBBYEFGYofTfZyODDCPMoMV7QaUpVGNKHMB8GA1UdIwQYMBaAFEKu+NexBjBGKrtMYo6DzwUKs4tJMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jZXJ0cy53ZWF0aGVyYXBpLmxhYi9jcmwvY3JsX2xpc3QuY3JsMCsGA1UdEQQkMCKGIGh0dHBzOi8vd2VhdGhlcmFwaS5sYWI6NTAyMS9maGlyMCoGA1UdJQEB/wQgMB4GCCsGAQUFBwMCBggrBgEFBQcDAQYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADaTQff7z0BZNgoKDkjxzZNKfUsHfWIsuOe8zfAfYzXAqUiyBWl8pdrL7EW9JoKLchQPC5grWW8uUfzknD3El0QGLgXNvm+imsk0NXaH0R9vEIafJhGXkZWIZx61GekoUQ8+7xEbf9gr5BGA3jMWAtkO6+LvZuhdkTd1k2RlVpl39Yx56Ivg/KpgRXM1PyISl1obbC/b5PCQ/t4kysTmkU9GVz1Z7+rUPcCP+fKFblsLLToVgxA13ozYRAF9/k2V9n/ZiHSOJmwPwLwBs9yHwsdefBlQ9G0Rzm9oU89G5o74HNlhInqD4wQspm+uhewwIAzRkGfL+t992nn1il8rt+VnnZ97rMIZ+cCjyvB0JmlsRQlngRt9cJbHp0OAo5jD8WJwbwgJ0Z3qClCvxZVwT9H5c+klre31ef61XrC0foPkX3TBSytnWh2iQkAdME6ChKl2RZKac2V4zCG8JgSRcP85lDooigsnBk5Sqmf3cifxm29Fte4X/0JG1IpSCLFLcaLyj2me0mVUNDnzIalLaBwwY4kNLPEppJhlFUUV16efaHwOesSQJvGk77tCGaGsG3kPUQcOa0tb2lYJho0Jnq6xymcNZuUQ5PLXmq6l7/gGJ7AqCb1fDghF0PlTwOkh+ZFiaja1YxzN9SsqsR9hyAUJt0mpzqzLNXjWa3PAcy+P";

        var cert = new X509Certificate2(Convert.FromBase64String(x5cArray!.First()));
        var tokenHandler = new JwtSecurityTokenHandler();

        tokenHandler.ValidateToken(_fixture.WellKnownUdap?.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuers = new[] { "http://localhost/fhir/r4" }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = new[] { tokenHeader.Alg }, //must match signing algorithm

        }, out SecurityToken valdatedToken);

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                                  X509ChainStatusFlags.Revoked |
                                  X509ChainStatusFlags.NotSignatureValid |
                                  X509ChainStatusFlags.InvalidBasicConstraints |
                                  X509ChainStatusFlags.CtlNotTimeValid |
                                  // X509ChainStatusFlags.OfflineRevocation |
                                  X509ChainStatusFlags.CtlNotSignatureValid;

        ValidateCertificateChain(cert, problemFlags).Should().BeTrue();
        _diagnosticsChainValidator.Called.Should().BeFalse();
    }

    [Fact]
    public void ValidateChainOffLineRevocationTest()
    {
        var jwt = new JwtSecurityToken(_fixture.WellKnownUdap?.SignedMetadata);
        var tokenHeader = jwt.Header;

        var x5cArray = JsonConvert.DeserializeObject<string[]>(tokenHeader.X5c);

        // bad keys
        // var x5cArray = new string[1];
        // x5cArray[0] = "MIIFVzCCAz+gAwIBAgIEAQIDBDANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJVUzEPMA0GA1UECBMGT3JlZ29uMREwDwYDVQQHEwhQb3J0bGFuZDEUMBIGA1UEChMLSG9ibyBDb2RpbmcxDzANBgNVBAsTBkFuY2hvcjEZMBcGA1UEAxMQVURBUC1UZXN0LUFuY2hvcjAeFw0yMjA4MzEyMDI4NDBaFw0yNDA5MDEyMDI4NDBaMG8xCzAJBgNVBAYTAlVTMQ8wDQYDVQQIEwZPcmVnb24xETAPBgNVBAcTCFBvcnRsYW5kMRQwEgYDVQQKEwtIb2JvIENvZGluZzENMAsGA1UECxMEVURBUDEXMBUGA1UEAxMOd2VhdGhlcmFwaS5sYWIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkU61gOhliibnE2L2SMX4bNE/WqVxpgdRyW2Ii7kbdW5f/eATAhWjrm1koKrCiR9/fH6hK/HEYPBgT/QKU6fTEgBjJEf51ouGHEZzYkEldKMZCjZnxCYRYbF+PhflhnLyj0R0NagH2OFzrrKj3qwPZ3WDSUDC/kxh7YNWJGnOo33bhD+gh+SYdq598cJiXsyfL1N9iTstXYKCKwmP+iJNQ5dV14dbDm693XlVe/G3JwADNzxRoIRVe9Yb9KcE7o7BIy18jUjJySfrAa3Y3Z9jX5ng89CVI3HHiQ9fVHrZjkYUaqe+0c88Asg3op3HPQNyk6bjKxgU7tHfZm5O+KyM9AgMBAAGjgfYwgfMwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwHQYDVR0OBBYEFGYofTfZyODDCPMoMV7QaUpVGNKHMB8GA1UdIwQYMBaAFEKu+NexBjBGKrtMYo6DzwUKs4tJMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jZXJ0cy53ZWF0aGVyYXBpLmxhYi9jcmwvY3JsX2xpc3QuY3JsMCsGA1UdEQQkMCKGIGh0dHBzOi8vd2VhdGhlcmFwaS5sYWI6NTAyMS9maGlyMCoGA1UdJQEB/wQgMB4GCCsGAQUFBwMCBggrBgEFBQcDAQYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADaTQff7z0BZNgoKDkjxzZNKfUsHfWIsuOe8zfAfYzXAqUiyBWl8pdrL7EW9JoKLchQPC5grWW8uUfzknD3El0QGLgXNvm+imsk0NXaH0R9vEIafJhGXkZWIZx61GekoUQ8+7xEbf9gr5BGA3jMWAtkO6+LvZuhdkTd1k2RlVpl39Yx56Ivg/KpgRXM1PyISl1obbC/b5PCQ/t4kysTmkU9GVz1Z7+rUPcCP+fKFblsLLToVgxA13ozYRAF9/k2V9n/ZiHSOJmwPwLwBs9yHwsdefBlQ9G0Rzm9oU89G5o74HNlhInqD4wQspm+uhewwIAzRkGfL+t992nn1il8rt+VnnZ97rMIZ+cCjyvB0JmlsRQlngRt9cJbHp0OAo5jD8WJwbwgJ0Z3qClCvxZVwT9H5c+klre31ef61XrC0foPkX3TBSytnWh2iQkAdME6ChKl2RZKac2V4zCG8JgSRcP85lDooigsnBk5Sqmf3cifxm29Fte4X/0JG1IpSCLFLcaLyj2me0mVUNDnzIalLaBwwY4kNLPEppJhlFUUV16efaHwOesSQJvGk77tCGaGsG3kPUQcOa0tb2lYJho0Jnq6xymcNZuUQ5PLXmq6l7/gGJ7AqCb1fDghF0PlTwOkh+ZFiaja1YxzN9SsqsR9hyAUJt0mpzqzLNXjWa3PAcy+P";

        var cert = new X509Certificate2(Convert.FromBase64String(x5cArray!.First()));
        var tokenHandler = new JwtSecurityTokenHandler();

        tokenHandler.ValidateToken(_fixture.WellKnownUdap?.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuers = new[] { "http://localhost/fhir/r4" }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = new[] { tokenHeader.Alg }, //must match signing algorithm

        }, out SecurityToken valdatedToken);

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid |
                           X509ChainStatusFlags.PartialChain;
        // X509ChainStatusFlags.RevocationStatusUnknown;

        //
        // Trusted anchor
        //
        ValidateCertificateChain(cert, problemFlags).Should().BeTrue();


        problemFlags = X509ChainStatusFlags.NotTimeValid |
                       X509ChainStatusFlags.Revoked |
                       X509ChainStatusFlags.NotSignatureValid |
                       X509ChainStatusFlags.InvalidBasicConstraints |
                       X509ChainStatusFlags.CtlNotTimeValid |
                       X509ChainStatusFlags.OfflineRevocation |
                       X509ChainStatusFlags.CtlNotSignatureValid |
                       X509ChainStatusFlags.RevocationStatusUnknown |
                       X509ChainStatusFlags.PartialChain;

        ValidateCertificateChain(cert, problemFlags).Should().BeFalse();

        _diagnosticsChainValidator.ActualErrorMessages.Any(m =>
                m.Contains("OfflineRevocation"))
            .Should().BeTrue();
    }

    public bool ValidateCertificateChain(X509Certificate2 issuedCertificate2, X509ChainStatusFlags problemFlags)
    {
        var certStore = _fixture.Services.GetService<ICertificateStore>();

        var anchors = certStore!.Resolve().Anchors
            .Where(c => c.Community == _fixture.Community)
            .OrderBy(c => X509Certificate2.CreateFromPem(c.Certificate).NotBefore)
            .Select(c => c.Certificate);

        var validator = new TrustChainValidator(new X509ChainPolicy(), problemFlags, _testOutputHelper.ToLogger<TrustChainValidator>());
        validator.Problem += _diagnosticsChainValidator.OnChainProblem;

        // Help while writing tests to see problems summarized.
        validator.Error += (certificate2, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.ChainElementStatus.Summarize(problemFlags));
        validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

        return validator.IsTrustedCertificate(issuedCertificate2, anchors.Select(a =>
            X509Certificate2.CreateFromPem(a)).ToArray().ToX509Collection(),
            certStore?.Resolve().RootCAs.ToArray().ToX509Collection()); 
    }

    public class FakeChainValidatorDiagnostics
    {
        public bool Called;

        private readonly List<string> _actualErrorMessages = new List<string>();
        public List<string> ActualErrorMessages
        {
            get { return _actualErrorMessages; }
        }

        public void OnChainProblem(X509ChainElement chainElement)
        {
            foreach (var chainElementStatus in chainElement.ChainElementStatus
                         .Where(s => (s.Status & TrustChainValidator.DefaultProblemFlags) != 0))
            {
                var problem = $"Trust ERROR ({chainElementStatus.Status}){chainElementStatus.StatusInformation}, {chainElement.Certificate}";
                _actualErrorMessages.Add(problem);
                Called = true;
            }
        }
    }
}
