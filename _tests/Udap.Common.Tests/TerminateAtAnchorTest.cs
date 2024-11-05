#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Udap.Common.Certificates;

namespace Udap.Common.Tests;
public class TerminateAtAnchorTest
{
    private X509Certificate2 cert;
    private X509Certificate2 anchor;

    public TerminateAtAnchorTest()
    {
        cert = new X509Certificate2(Path.Combine("CertStore/issued", "fhirlabs.net.client.pfx"), "udap-test");
        anchor = new X509Certificate2(Path.Combine("CertStore/intermediates", "SureFhirLabs_Intermediate.cer"));
    }
    [Fact]
    public void TestAnchorTermination()
    {
        var logger = CreateLogger();
        var chainPolicy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.Online,
            VerificationFlags = X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                X509VerificationFlags.IgnoreEndRevocationUnknown |
                                X509VerificationFlags.AllowUnknownCertificateAuthority
        };

        var validator = new TrustChainValidator(chainPolicy, logger);
        var diagnosticsChainValidator = SetupDiagnostics(validator);

        var anchors = new X509Certificate2Collection { anchor };

        var result = validator.IsTrustedCertificate("client_name", cert, null, anchors);
        result.Should().BeTrue(
            string.Join("\r\n", diagnosticsChainValidator.ActualProblemMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualErrorMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualUntrustedMessages));

        diagnosticsChainValidator.ActualErrorMessages.Count.Should().Be(0);
        diagnosticsChainValidator.ActualProblemMessages.Count.Should().Be(0);
        diagnosticsChainValidator.ActualUntrustedMessages.Count.Should().Be(0);
    }

    [Theory]
    [InlineData(X509VerificationFlags.IgnoreWrongUsage)]
    [InlineData(X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown)]
    [InlineData(X509VerificationFlags.IgnoreEndRevocationUnknown)]
    [InlineData(X509VerificationFlags.AllowUnknownCertificateAuthority)]
    [InlineData(X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                X509VerificationFlags.IgnoreEndRevocationUnknown)]
    [InlineData(X509VerificationFlags.IgnoreEndRevocationUnknown |
                X509VerificationFlags.AllowUnknownCertificateAuthority)]
    [InlineData(X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                X509VerificationFlags.AllowUnknownCertificateAuthority)]
    public void TestAnchorTermination_Fail(X509VerificationFlags verificationFlags)
    {
        var logger = CreateLogger();
        var chainPolicy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.Online,
            VerificationFlags = verificationFlags
        };

        var validator = new TrustChainValidator(chainPolicy, logger);
        var diagnosticsChainValidator = SetupDiagnostics(validator);

        X509Certificate2Collection anchors = new X509Certificate2Collection { anchor };

        var result = validator.IsTrustedCertificate("client_name", cert, null, anchors);
        result.Should().BeFalse(
            string.Join("\r\n", diagnosticsChainValidator.ActualProblemMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualErrorMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualUntrustedMessages));

        diagnosticsChainValidator.ActualErrorMessages.Count.Should().Be(0);
        diagnosticsChainValidator.ActualProblemMessages.Count.Should().Be(4);
        diagnosticsChainValidator.ActualUntrustedMessages.Count.Should().Be(2);
    }

    
    private static ILogger<TrustChainValidator> CreateLogger()
    {
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole(options =>
            {
                options.LogToStandardErrorThreshold = LogLevel.Trace;
            });
            builder.SetMinimumLevel(LogLevel.Trace);
        });

        return loggerFactory.CreateLogger<TrustChainValidator>();
    }

    private static FakeChainValidatorDiagnostics SetupDiagnostics(TrustChainValidator validator)
    {
        var diagnosticsChainValidator = new FakeChainValidatorDiagnostics();
        validator.Problem += diagnosticsChainValidator.OnChainProblem;
        validator.Error += diagnosticsChainValidator.OnCertificateError;
        validator.Untrusted += diagnosticsChainValidator.OnUntrusted;
        return diagnosticsChainValidator;
    }
}

public class FakeChainValidatorDiagnostics
{
    public bool Called;

    private readonly List<string> _actualProblemMessages = new List<string>();
    private readonly List<string> _actualErrorMessages = new List<string>();
    private readonly List<string> _actualUntrustedMessages = new List<string>();

    public List<string> ActualProblemMessages
    {
        get { return _actualProblemMessages; }
    }

    public List<string> ActualErrorMessages
    {
        get { return _actualErrorMessages; }
    }

    public List<string> ActualUntrustedMessages
    {
        get { return _actualUntrustedMessages; }
    }

    public void OnChainProblem(X509ChainElement chainElement)
    {
        foreach (var chainElementStatus in chainElement.ChainElementStatus)
        {
            var problem = $"Trust ERROR {chainElementStatus.StatusInformation}, {chainElement.Certificate}";
            _actualProblemMessages.Add(problem);
        }
    }

    public void OnCertificateError(X509Certificate2 certificate, Exception error)
    {
        _actualErrorMessages.Add(error.Message);
        //Logger.Error("RESOLVER ERROR {0}, {1}", resolver.GetType().Name, error.Message);
    }

    public void OnUntrusted(X509Certificate2 certificate)
    {
        _actualUntrustedMessages.Add($"\r\n Untrusted Certificate: {certificate}");
        //Logger.Error("RESOLVER ERROR {0}, {1}", resolver.GetType().Name, error.Message);
    }
}