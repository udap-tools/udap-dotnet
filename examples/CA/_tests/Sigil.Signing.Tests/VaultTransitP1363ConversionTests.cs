#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using Shouldly;
using Sigil.Vault;

namespace Sigil.Signing.Tests;

/// <summary>
/// Tests for the P1363-to-DER conversion used by VaultTransitSigningProvider.
/// Vault returns ECDSA signatures in IEEE P1363 format (r || s), but BouncyCastle
/// and .NET X.509 expect DER-encoded signatures. This conversion is critical for
/// certificate validity.
/// </summary>
public class VaultTransitP1363ConversionTests
{
    [Fact]
    public void ConvertP1363ToDer_P256Signature_ProducesValidDer()
    {
        // Generate a real P1363 signature using .NET
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var data = "test data"u8.ToArray();
        var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        // Convert to DER
        var der = VaultTransitSigningProvider.ConvertP1363ToDer(p1363);

        // Verify the DER signature
        var isValid = ecdsa.VerifyData(data, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        isValid.ShouldBeTrue("DER-converted signature should verify against original key");
    }

    [Fact]
    public void ConvertP1363ToDer_P384Signature_ProducesValidDer()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var data = "test data for P384"u8.ToArray();
        var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA384, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var der = VaultTransitSigningProvider.ConvertP1363ToDer(p1363);

        var isValid = ecdsa.VerifyData(data, der, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence);
        isValid.ShouldBeTrue();
    }

    [Fact]
    public void ConvertP1363ToDer_OutputStartsWithSequenceTag()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var data = "test"u8.ToArray();
        var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var der = VaultTransitSigningProvider.ConvertP1363ToDer(p1363);

        der[0].ShouldBe((byte)0x30, "DER SEQUENCE tag");
        der[2].ShouldBe((byte)0x02, "first DER INTEGER tag (r)");
    }

    [Fact]
    public void ConvertP1363ToDer_HandlesHighBitPadding()
    {
        // Create a known P1363 signature where r has high bit set (needs 0x00 pad)
        var halfLen = 32; // P-256
        var p1363 = new byte[halfLen * 2];

        // Set r with high bit = 1 (needs padding in DER)
        p1363[0] = 0x80;
        for (int i = 1; i < halfLen; i++) p1363[i] = 0x42;

        // Set s normally
        p1363[halfLen] = 0x01;
        for (int i = halfLen + 1; i < p1363.Length; i++) p1363[i] = 0x23;

        var der = VaultTransitSigningProvider.ConvertP1363ToDer(p1363);

        // r should have a leading 0x00 pad
        der[0].ShouldBe((byte)0x30); // SEQUENCE
        der[2].ShouldBe((byte)0x02); // INTEGER
        der[3].ShouldBe((byte)(halfLen + 1)); // length includes pad
        der[4].ShouldBe((byte)0x00); // padding byte
        der[5].ShouldBe((byte)0x80); // original first byte
    }

    [Fact]
    public void ConvertP1363ToDer_TrimsLeadingZeros()
    {
        var halfLen = 32;
        var p1363 = new byte[halfLen * 2];

        // r starts with several leading zeros
        p1363[0] = 0x00;
        p1363[1] = 0x00;
        p1363[2] = 0x01;
        for (int i = 3; i < halfLen; i++) p1363[i] = 0x42;

        // s is normal
        p1363[halfLen] = 0x42;
        for (int i = halfLen + 1; i < p1363.Length; i++) p1363[i] = 0x23;

        var der = VaultTransitSigningProvider.ConvertP1363ToDer(p1363);

        // r INTEGER should have trimmed leading zeros
        der[2].ShouldBe((byte)0x02); // INTEGER tag
        var rLen = der[3];
        rLen.ShouldBe((byte)(halfLen - 2)); // trimmed 2 leading zeros
    }

    [Fact]
    public void ConvertP1363ToDer_RoundTrip_MultipleIterations()
    {
        // Fuzz-style test: generate many signatures and verify round-trip
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var data = new byte[100];
        Random.Shared.NextBytes(data);

        for (int i = 0; i < 50; i++)
        {
            var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA384,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var der = VaultTransitSigningProvider.ConvertP1363ToDer(p1363);

            var isValid = ecdsa.VerifyData(data, der, HashAlgorithmName.SHA384,
                DSASignatureFormat.Rfc3279DerSequence);
            isValid.ShouldBeTrue($"round-trip iteration {i} should produce valid DER");

            // Vary the data for each iteration
            data[i % data.Length] ^= 0xFF;
        }
    }
}
