#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Shouldly;
using Sigil.Common.Data.Entities;
using Sigil.Common.Validators;

namespace Sigil.Signing.Tests;

public class IssuanceValidatorTests
{
    private readonly IssuanceValidator _validator = new();

    [Fact]
    public void CompareTemplateUrls_NoChanges_ReturnsEmpty()
    {
        var original = new List<string> { "https://pki.example.com/crls/CA.crl" };
        var template = new List<string> { "https://pki.example.com/crls/CA.crl" };

        var warnings = _validator.CompareTemplateUrls(original, [], template, []);

        warnings.ShouldBeEmpty();
    }

    [Fact]
    public void CompareTemplateUrls_CdpAdded_ReturnsWarning()
    {
        var warnings = _validator.CompareTemplateUrls(
            [], [],
            ["https://new.com/crls/CA.crl"], []);

        warnings.ShouldHaveSingleItem();
        warnings[0].Category.ShouldBe("CDP");
        warnings[0].Message.ShouldContain("added");
    }

    [Fact]
    public void CompareTemplateUrls_CdpRemoved_ReturnsWarning()
    {
        var warnings = _validator.CompareTemplateUrls(
            ["https://old.com/crls/CA.crl"], [],
            [], []);

        warnings.ShouldHaveSingleItem();
        warnings[0].Category.ShouldBe("CDP");
        warnings[0].Message.ShouldContain("removed");
    }

    [Fact]
    public void CompareTemplateUrls_AiaChanged_ReturnsBothWarnings()
    {
        var warnings = _validator.CompareTemplateUrls(
            [], ["https://old.com/certs/CA.cer"],
            [], ["https://new.com/certs/CA.cer"]);

        warnings.Count.ShouldBe(2);
        warnings.ShouldContain(w => w.Message.Contains("removed"));
        warnings.ShouldContain(w => w.Message.Contains("added"));
    }

    [Fact]
    public void CompareTemplateUrls_CaseInsensitive()
    {
        var warnings = _validator.CompareTemplateUrls(
            ["HTTPS://PKI.EXAMPLE.COM/crls/CA.crl"], [],
            ["https://pki.example.com/crls/CA.crl"], []);

        warnings.ShouldBeEmpty();
    }

    [Fact]
    public void CompareTemplateUrls_MultipleChanges_ReturnsAll()
    {
        var warnings = _validator.CompareTemplateUrls(
            ["https://old.com/crls/CA.crl"], ["https://old.com/certs/CA.cer"],
            ["https://new.com/crls/CA.crl"], ["https://new.com/certs/CA.cer"]);

        warnings.Count.ShouldBe(4);
        warnings.Count(w => w.Category == "CDP").ShouldBe(2);
        warnings.Count(w => w.Category == "AIA").ShouldBe(2);
    }

    [Fact]
    public void ExpandCdpTemplates_WithBaseUrls_ExpandsPlaceholders()
    {
        var template = new CertificateTemplate
        {
            IncludeCdp = true,
            CdpUrlTemplate = "{BaseUrl}/crls/{CAName}.crl"
        };

        var result = _validator.ExpandCdpTemplates(
            template,
            ["https://pki.example.com"],
            "Root-CA");

        result.ShouldHaveSingleItem().ShouldBe("https://pki.example.com/crls/Root-CA.crl");
    }

    [Fact]
    public void ExpandAiaTemplates_WithBaseUrls_ExpandsPlaceholders()
    {
        var template = new CertificateTemplate
        {
            IncludeAia = true,
            AiaUrlTemplate = "{BaseUrl}/certs/{CAName}.cer"
        };

        var result = _validator.ExpandAiaTemplates(
            template,
            ["https://pki.example.com"],
            "Root-CA");

        result.ShouldHaveSingleItem().ShouldBe("https://pki.example.com/certs/Root-CA.cer");
    }

    [Fact]
    public void ExpandCdpTemplates_DefaultTemplate_WhenNoCustomTemplate()
    {
        var template = new CertificateTemplate
        {
            IncludeCdp = true,
            CdpUrlTemplate = null
        };

        var result = _validator.ExpandCdpTemplates(
            template,
            ["https://pki.example.com"],
            "Intermediate");

        result.ShouldHaveSingleItem().ShouldBe("https://pki.example.com/crls/Intermediate.crl");
    }

    [Fact]
    public void ExpandCdpTemplates_NotEnabled_ReturnsEmpty()
    {
        var template = new CertificateTemplate
        {
            IncludeCdp = false,
            CdpUrlTemplate = "{BaseUrl}/crls/{CAName}.crl"
        };

        var result = _validator.ExpandCdpTemplates(template, ["https://pki.example.com"], "CA");

        result.ShouldBeEmpty();
    }

    [Fact]
    public void ExpandCdpTemplates_MultipleBaseUrls_ExpandsAll()
    {
        var template = new CertificateTemplate
        {
            IncludeCdp = true,
            CdpUrlTemplate = "{BaseUrl}/crls/{CAName}.crl"
        };

        var result = _validator.ExpandCdpTemplates(
            template,
            ["https://a.com", "https://b.com"],
            "CA");

        result.Count.ShouldBe(2);
        result[0].ShouldBe("https://a.com/crls/CA.crl");
        result[1].ShouldBe("https://b.com/crls/CA.crl");
    }

    [Fact]
    public void ExpandCdpTemplates_NoBaseUrls_ExpandsCaNameOnly()
    {
        var template = new CertificateTemplate
        {
            IncludeCdp = true,
            CdpUrlTemplate = "{BaseUrl}/crls/{CAName}.crl"
        };

        var result = _validator.ExpandCdpTemplates(template, [], "My-CA");

        result.ShouldHaveSingleItem().ShouldContain("My-CA.crl");
    }

    [Fact]
    public void FindSupersededCaIds_SingleCa_ReturnsEmpty()
    {
        var cas = new List<CaCertificate>
        {
            new() { Id = 1, Subject = "CN=CA", NotBefore = DateTime.UtcNow }
        };

        var result = _validator.FindSupersededCaIds(cas);

        result.ShouldBeEmpty();
    }

    [Fact]
    public void FindSupersededCaIds_TwoCasSameSubject_OlderIsSuperseded()
    {
        var cas = new List<CaCertificate>
        {
            new() { Id = 1, Subject = "CN=Intermediate CA", NotBefore = DateTime.UtcNow.AddDays(-365) },
            new() { Id = 2, Subject = "CN=Intermediate CA", NotBefore = DateTime.UtcNow }
        };

        var result = _validator.FindSupersededCaIds(cas);

        result.ShouldHaveSingleItem().ShouldBe(1);
    }

    [Fact]
    public void FindSupersededCaIds_DifferentSubjects_NoneSuperseded()
    {
        var cas = new List<CaCertificate>
        {
            new() { Id = 1, Subject = "CN=CA One", NotBefore = DateTime.UtcNow.AddDays(-365) },
            new() { Id = 2, Subject = "CN=CA Two", NotBefore = DateTime.UtcNow }
        };

        var result = _validator.FindSupersededCaIds(cas);

        result.ShouldBeEmpty();
    }

    [Fact]
    public void FindSupersededCaIds_ArchivedCa_Excluded()
    {
        var cas = new List<CaCertificate>
        {
            new() { Id = 1, Subject = "CN=CA", NotBefore = DateTime.UtcNow.AddDays(-365) },
            new() { Id = 2, Subject = "CN=CA", NotBefore = DateTime.UtcNow, IsArchived = true }
        };

        var result = _validator.FindSupersededCaIds(cas);

        result.ShouldBeEmpty();
    }

    [Fact]
    public void FindSupersededCaIds_RevokedCa_Excluded()
    {
        var cas = new List<CaCertificate>
        {
            new() { Id = 1, Subject = "CN=CA", NotBefore = DateTime.UtcNow.AddDays(-365) },
            new() { Id = 2, Subject = "CN=CA", NotBefore = DateTime.UtcNow, IsRevoked = true }
        };

        var result = _validator.FindSupersededCaIds(cas);

        result.ShouldBeEmpty();
    }

    [Fact]
    public void FindSupersededCaIds_ThreeVersions_TwoSuperseded()
    {
        var cas = new List<CaCertificate>
        {
            new() { Id = 1, Subject = "CN=CA", NotBefore = DateTime.UtcNow.AddDays(-730) },
            new() { Id = 2, Subject = "CN=CA", NotBefore = DateTime.UtcNow.AddDays(-365) },
            new() { Id = 3, Subject = "CN=CA", NotBefore = DateTime.UtcNow }
        };

        var result = _validator.FindSupersededCaIds(cas);

        result.Count.ShouldBe(2);
        result.ShouldContain(1);
        result.ShouldContain(2);
    }

    [Fact]
    public void FindSupersededCaIds_CaseInsensitiveSubject()
    {
        var cas = new List<CaCertificate>
        {
            new() { Id = 1, Subject = "CN=intermediate CA", NotBefore = DateTime.UtcNow.AddDays(-365) },
            new() { Id = 2, Subject = "CN=Intermediate CA", NotBefore = DateTime.UtcNow }
        };

        var result = _validator.FindSupersededCaIds(cas);

        result.ShouldHaveSingleItem().ShouldBe(1);
    }
}
