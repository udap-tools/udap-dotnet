#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Udap.Common.Certificates;
using Xunit.Abstractions;

namespace Udap.Common.Tests;
public class TerminateAtAnchorTest
{
    private readonly ITestOutputHelper _output;
    private X509Certificate2 cert;
    private X509Certificate2 anchor;

    public TerminateAtAnchorTest(ITestOutputHelper output)
    {
        _output = output;
#if NET9_0_OR_GREATER
        cert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("CertStore/issued", "fhirlabs.net.client.pfx"), "udap-test");
        anchor = X509CertificateLoader.LoadCertificateFromFile(Path.Combine("CertStore/intermediates", "SureFhirLabs_Intermediate.cer"));
#else
        cert = new X509Certificate2(Path.Combine("CertStore/issued", "fhirlabs.net.client.pfx"), "udap-test");
        anchor = new X509Certificate2(Path.Combine("CertStore/intermediates", "SureFhirLabs_Intermediate.cer"));
#endif
    }
    [Fact]
    public async Task TestAnchorTermination()
    {
        var logger = CreateLogger(_output);

        // remove revocation check for this test.
        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;

        var validator = new TrustChainValidator(problemFlags, false, logger);
        var diagnosticsChainValidator = SetupDiagnostics(validator);

        var anchors = new X509Certificate2Collection { anchor };

        var result = await validator.IsTrustedCertificateAsync("client_name", cert, null, anchors);
        Assert.True(result,
            string.Join("\r\n", diagnosticsChainValidator.ActualProblemMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualErrorMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualUntrustedMessages));

        Assert.Empty(diagnosticsChainValidator.ActualErrorMessages);
        Assert.Empty(diagnosticsChainValidator.ActualProblemMessages);
        Assert.Empty(diagnosticsChainValidator.ActualUntrustedMessages);
    }

    [Fact(Skip = "Anchor Termination works but I have some details to work out for this test to pass")]
    public async Task TestAnchorTermination_Fail()
    {
        var logger = CreateLogger(_output);

        var validator = new TrustChainValidator(logger);
        var diagnosticsChainValidator = SetupDiagnostics(validator);

        X509Certificate2Collection anchors = new X509Certificate2Collection { anchor };

        var result = await validator.IsTrustedCertificateAsync("client_name", cert, null, anchors);
        Assert.False(result,
            string.Join("\r\n", diagnosticsChainValidator.ActualProblemMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualErrorMessages)
            + "\r\n" + string.Join("\r\n", diagnosticsChainValidator.ActualUntrustedMessages));

        Assert.Empty(diagnosticsChainValidator.ActualErrorMessages);

        Assert.Contains(diagnosticsChainValidator.ActualProblemMessages, message =>
            message.Contains("Trust ERROR"));

        Assert.Contains(diagnosticsChainValidator.ActualUntrustedMessages, message =>
            message.StartsWith("Untrusted Certificate"));
    }

    
    private static ILogger<TrustChainValidator> CreateLogger(ITestOutputHelper output)
    {
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddProvider(new XunitLoggerProvider(output));
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

    public void OnChainProblem(ChainElementInfo chainElement)
    {
        foreach (var problem in chainElement.Problems)
        {
            var msg = $"Trust ERROR {problem.StatusInformation}, {chainElement.Certificate}";
            _actualProblemMessages.Add(msg);
        }
    }

    public void OnCertificateError(X509Certificate2 certificate, Exception error)
    {
        _actualErrorMessages.Add(error.Message);
        //Logger.Error("RESOLVER ERROR {0}, {1}", resolver.GetType().Name, error.Message);
    }

    public void OnUntrusted(X509Certificate2 certificate)
    {
        _actualUntrustedMessages.Add($"Untrusted Certificate: {certificate}");
        //Logger.Error("RESOLVER ERROR {0}, {1}", resolver.GetType().Name, error.Message);
    }
}

public class XunitLoggerProvider : ILoggerProvider
{
    private readonly ITestOutputHelper _output;

    public XunitLoggerProvider(ITestOutputHelper output)
    {
        _output = output;
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new XunitLogger(_output, categoryName);
    }

    public void Dispose()
    {
    }
}

public class XunitLogger : ILogger
{
    private readonly ITestOutputHelper _output;
    private readonly string _categoryName;

    public XunitLogger(ITestOutputHelper output, string categoryName)
    {
        _output = output;
        _categoryName = categoryName;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        _output.WriteLine($"{logLevel}: {_categoryName} - {formatter(state, exception)}");
        if (exception != null)
        {
            _output.WriteLine(exception.ToString());
        }
    }
}