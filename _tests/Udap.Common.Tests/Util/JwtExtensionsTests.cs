#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Util.Extensions;
using Xunit;

namespace Udap.Common.Tests.Util;

public class JwtExtensionsTests
{
    private readonly X509Certificate2 _testCert;

    public JwtExtensionsTests()
    {
#if NET9_0_OR_GREATER
        _testCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        _testCert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
    }

    private string BuildJwtWithX5c(params X509Certificate2[] certs)
    {
        var x5cArray = new JsonArray();
        foreach (var cert in certs)
        {
            x5cArray.Add(Convert.ToBase64String(cert.RawData));
        }

        var header = new JsonObject
        {
            ["alg"] = "none",
            ["x5c"] = x5cArray
        };

        var payload = new JsonObject
        {
            ["iss"] = "test"
        };

        var headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));

        return $"{headerEncoded}.{payloadEncoded}.";
    }

    private string BuildJwtWithoutX5c()
    {
        var header = new JsonObject
        {
            ["alg"] = "none"
        };

        var payload = new JsonObject
        {
            ["iss"] = "test"
        };

        var headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));

        return $"{headerEncoded}.{payloadEncoded}.";
    }

    private string BuildJwtWithX5cValue(JsonNode? x5cValue)
    {
        var header = new JsonObject
        {
            ["alg"] = "none",
            ["x5c"] = x5cValue
        };

        var payload = new JsonObject
        {
            ["iss"] = "test"
        };

        var headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));

        return $"{headerEncoded}.{payloadEncoded}.";
    }

    [Fact]
    public void Getx5cArray_WithCerts_ReturnsJsonArray()
    {
        var jwtString = BuildJwtWithX5c(_testCert);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.Getx5cArray();

        Assert.NotNull(result);
        Assert.Single(result!);
    }

    [Fact]
    public void Getx5cArray_NoX5c_ReturnsEmptyArray()
    {
        var jwtString = BuildJwtWithoutX5c();
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.Getx5cArray();

        Assert.NotNull(result);
        Assert.Empty(result!);
    }

    [Fact]
    public void GetCertificateList_WithValidCerts_ReturnsCertificates()
    {
#if NET9_0_OR_GREATER
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif
        var jwtString = BuildJwtWithX5c(_testCert, intermediateCert);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.GetCertificateList();

        Assert.NotNull(result);
        Assert.Equal(2, result!.Count);
        Assert.Equal(_testCert.Thumbprint, result.First().Thumbprint);
        Assert.Equal(intermediateCert.Thumbprint, result.Last().Thumbprint);
    }

    [Fact]
    public void GetCertificateList_NoX5c_ReturnsNull()
    {
        var jwtString = BuildJwtWithoutX5c();
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.GetCertificateList();

        Assert.Null(result);
    }

    [Fact]
    public void GetPublicCertificate_JWT_WithCerts_ReturnsFirstCert()
    {
        var jwtString = BuildJwtWithX5c(_testCert);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.GetPublicCertificate();

        Assert.NotNull(result);
        Assert.Equal(_testCert.Thumbprint, result!.Thumbprint);
    }

    [Fact]
    public void GetPublicCertificate_JWT_NoX5c_ReturnsNull()
    {
        var jwtString = BuildJwtWithoutX5c();
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.GetPublicCertificate();

        Assert.Null(result);
    }

    [Fact]
    public void GetPublicCertificate_JsonArray_WithCerts_ReturnsFirstCert()
    {
        var jsonArray = new JsonArray
        {
            Convert.ToBase64String(_testCert.RawData)
        };

        var result = jsonArray.GetPublicCertificate();

        Assert.NotNull(result);
        Assert.Equal(_testCert.Thumbprint, result!.Thumbprint);
    }

    [Fact]
    public void GetPublicCertificate_JsonArray_Empty_ReturnsNull()
    {
        var jsonArray = new JsonArray();

        var result = jsonArray.GetPublicCertificate();

        Assert.Null(result);
    }

    [Fact]
    public void GetPublicCertificate_JsonArray_MultipleCerts_ReturnsFirst()
    {
#if NET9_0_OR_GREATER
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif
        var jsonArray = new JsonArray
        {
            Convert.ToBase64String(_testCert.RawData),
            Convert.ToBase64String(intermediateCert.RawData)
        };

        var result = jsonArray.GetPublicCertificate();

        Assert.NotNull(result);
        Assert.Equal(_testCert.Thumbprint, result!.Thumbprint);
    }

    [Fact]
    public void GetCertificateList_X5cIsNotArray_ReturnsNull()
    {
        var jwtString = BuildJwtWithX5cValue(JsonValue.Create(42));
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.GetCertificateList();

        Assert.Null(result);
    }

    [Fact]
    public void GetCertificateList_ArrayContainsNull_ReturnsNull()
    {
        var x5cArray = new JsonArray { null };
        var jwtString = BuildJwtWithX5cValue(x5cArray);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.GetCertificateList();

        Assert.Null(result);
    }

    [Fact]
    public void Getx5cArray_X5cIsNotArray_ReturnsNull()
    {
        var jwtString = BuildJwtWithX5cValue(JsonValue.Create(42));
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.Getx5cArray();

        Assert.Null(result);
    }

    [Fact]
    public void GetPublicCertificate_JWT_X5cIsNotArray_ReturnsNull()
    {
        var jwtString = BuildJwtWithX5cValue(JsonValue.Create(42));
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(jwtString);

        var result = jwt.GetPublicCertificate();

        Assert.Null(result);
    }

    [Fact]
    public void GetPublicCertificate_JsonArray_NullFirstNode_ReturnsNull()
    {
        var jsonArray = new JsonArray { null };

        var result = jsonArray.GetPublicCertificate();

        Assert.Null(result);
    }
}
