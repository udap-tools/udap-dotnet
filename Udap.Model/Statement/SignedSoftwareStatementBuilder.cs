#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Math.EC;
using Udap.Model.Registration;
using ECCurve = System.Security.Cryptography.ECCurve;

namespace Udap.Model.Statement;
public class SignedSoftwareStatementBuilder<T> where T: class, ISoftwareStatementSerializer
{
    private readonly X509Certificate2 _certificate;
    private readonly T _document;

    private SignedSoftwareStatementBuilder(X509Certificate2 certificate, T document)
    {
        _certificate = certificate;
        _document = document;
    }

    public static SignedSoftwareStatementBuilder<T> Create(X509Certificate2 certificate, T document)
    {
        return new SignedSoftwareStatementBuilder<T>(certificate, document);
    }
     
    //
    // No With items...
    // There are plenty of interesting scenarios like loading the x5c hierarchy where
    // we could add more builder methods
    //

    public string Build(string? algorithm = UdapConstants.SupportedAlgorithm.RS256)
    {
        algorithm ??= UdapConstants.SupportedAlgorithm.RS256;

        var securityKey = new X509SecurityKey(_certificate);
        var signingCredentials = new SigningCredentials(securityKey, algorithm);

        var pem = Convert.ToBase64String(_certificate.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = _document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        return signedSoftwareStatement;
    }

#if NET5_0_OR_GREATER
    public string BuildECDSA(string? algorithm = UdapConstants.SupportedAlgorithm.ES384)
    {
        algorithm ??= UdapConstants.SupportedAlgorithm.ES384;

        var key = _certificate.GetECDsaPrivateKey();

        byte[] encryptedPrivKeyBytes = key.ExportEncryptedPkcs8PrivateKey(
            "udap-test",
            new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: 100_000));

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        ecdsa.ImportEncryptedPkcs8PrivateKey("udap-test".AsSpan(), encryptedPrivKeyBytes.AsSpan(), out int bytesRead);
        var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), algorithm);

        var pem = Convert.ToBase64String(_certificate.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = _document.Base64UrlEncode();
        var input = string.Concat(encodedHeader, ".", encodedPayload);
        var encodedSignature = JwtTokenUtilities.CreateEncodedSignature(input, signingCredentials);

        // var encodedSignature =
        //     JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
        //         signingCredentials);



        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        return signedSoftwareStatement;
    }
#endif
}