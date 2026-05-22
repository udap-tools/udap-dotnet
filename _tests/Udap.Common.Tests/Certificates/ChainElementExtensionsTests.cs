#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Certificates;

namespace Udap.Common.Tests.Certificates;

public class ChainElementExtensionsTests
{
    [Fact]
    public void Summarize_Problems_MatchingFlags_IncludesMatchingProblems()
    {
        var problems = new List<ChainProblem>
        {
            new ChainProblem(ChainProblemStatus.NotTimeValid, "Certificate has expired"),
            new ChainProblem(ChainProblemStatus.Revoked, "Certificate has been revoked"),
            new ChainProblem(ChainProblemStatus.UntrustedRoot, "Root is not trusted")
        };

        var result = problems.Summarize(ChainProblemStatus.NotTimeValid | ChainProblemStatus.Revoked);

        Assert.Contains("(NotTimeValid) Certificate has expired", result);
        Assert.Contains("(Revoked) Certificate has been revoked", result);
        Assert.DoesNotContain("UntrustedRoot", result);
    }

    [Fact]
    public void Summarize_Problems_NoMatchingFlags_ReturnsEmptyString()
    {
        var problems = new List<ChainProblem>
        {
            new ChainProblem(ChainProblemStatus.NotTimeValid, "Certificate has expired")
        };

        var result = problems.Summarize(ChainProblemStatus.Revoked);

        Assert.Equal("", result);
    }

    [Fact]
    public void Summarize_Problems_EmptyList_ReturnsEmptyString()
    {
        var problems = new List<ChainProblem>();

        var result = problems.Summarize(ChainProblemStatus.NotTimeValid);

        Assert.Equal("", result);
    }

    [Fact]
    public void Summarize_Problems_NoneStatus_NeverMatches()
    {
        var problems = new List<ChainProblem>
        {
            new ChainProblem(ChainProblemStatus.None, "No problem")
        };

        var result = problems.Summarize(ChainProblemStatus.NotTimeValid);

        Assert.Equal("", result);
    }

    [Fact]
    public void Summarize_ChainElements_WithProblems_IncludesNonNoneProblems()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#else
        var cert = new X509Certificate2(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#endif

        var elements = new List<ChainElementInfo>
        {
            new ChainElementInfo(cert, new List<ChainProblem>
            {
                new ChainProblem(ChainProblemStatus.NotTimeValid, "Certificate has expired")
            })
        };

        var result = elements.Summarize();

        Assert.Contains("NotTimeValid", result);
        Assert.Contains("Certificate has expired", result);
    }

    [Fact]
    public void Summarize_ChainElements_WithNoneStatus_ExcludesNoneProblems()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#else
        var cert = new X509Certificate2(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#endif

        var elements = new List<ChainElementInfo>
        {
            new ChainElementInfo(cert, new List<ChainProblem>
            {
                new ChainProblem(ChainProblemStatus.None, "No problem")
            })
        };

        var result = elements.Summarize();

        Assert.DoesNotContain("No problem", result);
    }

    [Fact]
    public void Summarize_ChainElements_EmptyList_ReturnsNewlineOnly()
    {
        var elements = new List<ChainElementInfo>();

        var result = elements.Summarize();

        Assert.Equal(Environment.NewLine, result);
    }

    [Fact]
    public void Summarize_ChainElements_NoProblems_ReturnsNewlineOnly()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#else
        var cert = new X509Certificate2(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#endif

        var elements = new List<ChainElementInfo>
        {
            new ChainElementInfo(cert)
        };

        var result = elements.Summarize();

        Assert.Equal(Environment.NewLine, result);
    }

    [Fact]
    public void HasProblems_WithProblems_ReturnsTrue()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#else
        var cert = new X509Certificate2(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#endif

        var element = new ChainElementInfo(cert, new List<ChainProblem>
        {
            new ChainProblem(ChainProblemStatus.NotTimeValid, "Expired")
        });

        Assert.True(element.HasProblems);
    }

    [Fact]
    public void HasProblems_NoProblems_ReturnsFalse()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#else
        var cert = new X509Certificate2(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#endif

        var element = new ChainElementInfo(cert);

        Assert.False(element.HasProblems);
    }

    [Fact]
    public void Summarize_ChainElements_MultipleElementsWithMixedProblems()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#else
        var cert = new X509Certificate2(
            Path.Combine(AppContext.BaseDirectory, "CertStore/issued/fhirlabs.net.client.pfx"),
            "udap-test");
#endif

        var elements = new List<ChainElementInfo>
        {
            new ChainElementInfo(cert, new List<ChainProblem>
            {
                new ChainProblem(ChainProblemStatus.Revoked, "Revoked cert"),
                new ChainProblem(ChainProblemStatus.None, "Should be excluded")
            }),
            new ChainElementInfo(cert, new List<ChainProblem>
            {
                new ChainProblem(ChainProblemStatus.UntrustedRoot, "Untrusted root cert")
            })
        };

        var result = elements.Summarize();

        Assert.Contains("Revoked", result);
        Assert.Contains("Untrusted root cert", result);
        Assert.DoesNotContain("Should be excluded", result);
    }
}
