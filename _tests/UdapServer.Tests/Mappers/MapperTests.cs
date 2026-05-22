#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Server.Storage.Mappers;
using AnchorEntity = Udap.Server.Storage.Entities.Anchor;
using CommunityEntity = Udap.Server.Storage.Entities.Community;
using CertificationEntity = Udap.Server.Storage.Entities.Certification;
using IntermediateEntity = Udap.Server.Storage.Entities.Intermediate;
using TieredClientEntity = Udap.Server.Storage.Entities.TieredClient;
using AnchorModel = Udap.Common.Models.Anchor;
using CommunityModel = Udap.Common.Models.Community;
using CertificationModel = Udap.Common.Models.Certification;
using IntermediateModel = Udap.Common.Models.Intermediate;
using TieredClientModel = Udap.Common.Models.TieredClient;

namespace UdapServer.Tests.Mappers;

public class CommunityMapperTests
{
    [Fact]
    public void ToModel_MapsAllProperties()
    {
        var entity = new CommunityEntity
        {
            Id = 1,
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true
        };

        var model = entity.ToModel();

        Assert.Equal(1, model.Id);
        Assert.Equal("udap://fhirlabs.net", model.Name);
        Assert.True(model.Enabled);
        Assert.True(model.Default);
    }

    [Fact]
    public void ToModel_NullAnchorsAndCertifications_MapsAsNull()
    {
        var entity = new CommunityEntity
        {
            Id = 2,
            Name = "test",
            Anchors = null,
            Certifications = null
        };

        var model = entity.ToModel();

        Assert.Null(model.Anchors);
        Assert.Null(model.Certifications);
    }

    [Fact]
    public void ToModel_WithCertifications_MapsCertifications()
    {
        var entity = new CommunityEntity
        {
            Id = 1,
            Name = "test",
            Certifications = new List<CertificationEntity>
            {
                new() { Id = 10, Name = "TEFCA" },
                new() { Id = 20, Name = "SSRAA" }
            }
        };

        var model = entity.ToModel();

        Assert.NotNull(model.Certifications);
        Assert.Equal(2, model.Certifications.Count);
        Assert.Contains(model.Certifications, c => c.Id == 10 && c.Name == "TEFCA");
        Assert.Contains(model.Certifications, c => c.Id == 20 && c.Name == "SSRAA");
    }

    [Fact]
    public void ToEntity_MapsAllProperties()
    {
        var model = new CommunityModel
        {
            Id = 3,
            Name = "udap://test",
            Enabled = true,
            Default = false
        };

        var entity = model.ToEntity();

        Assert.Equal(3, entity.Id);
        Assert.Equal("udap://test", entity.Name);
        Assert.True(entity.Enabled);
        Assert.False(entity.Default);
    }

    [Fact]
    public void ToEntity_NullAnchorsAndCertifications_MapsAsNull()
    {
        var model = new CommunityModel
        {
            Id = 1,
            Name = "test",
            Anchors = null,
            Certifications = null
        };

        var entity = model.ToEntity();

        Assert.Null(entity.Anchors);
        Assert.Null(entity.Certifications);
    }

    [Fact]
    public void ToEntity_WithCertifications_MapsCertifications()
    {
        var model = new CommunityModel
        {
            Id = 1,
            Name = "test",
            Certifications = new List<CertificationModel>
            {
                new() { Id = 5, Name = "Cert1" }
            }
        };

        var entity = model.ToEntity();

        Assert.NotNull(entity.Certifications);
        Assert.Single(entity.Certifications);
        var cert = entity.Certifications.First();
        Assert.Equal(5, cert.Id);
        Assert.Equal("Cert1", cert.Name);
    }

    [Fact]
    public void RoundTrip_EntityToModelToEntity_PreservesValues()
    {
        var original = new CommunityEntity
        {
            Id = 7,
            Name = "udap://roundtrip",
            Enabled = true,
            Default = false
        };

        var roundTripped = original.ToModel().ToEntity();

        Assert.Equal(original.Id, roundTripped.Id);
        Assert.Equal(original.Name, roundTripped.Name);
        Assert.Equal(original.Enabled, roundTripped.Enabled);
        Assert.Equal(original.Default, roundTripped.Default);
    }
}

public class TieredClientMapperTests
{
    [Fact]
    public void ToModel_MapsAllProperties()
    {
        var entity = new TieredClientEntity
        {
            Id = 1,
            ClientName = "Test Client",
            ClientId = "client-123",
            IdPBaseUrl = "https://idp.example.com",
            RedirectUri = "https://app.example.com/callback",
            ClientUriSan = "https://app.example.com",
            CommunityId = 5,
            Enabled = true,
            TokenEndpoint = "https://idp.example.com/token"
        };

        var model = entity.ToModel();

        Assert.Equal(1, model.Id);
        Assert.Equal("Test Client", model.ClientName);
        Assert.Equal("client-123", model.ClientId);
        Assert.Equal("https://idp.example.com", model.IdPBaseUrl);
        Assert.Equal("https://app.example.com/callback", model.RedirectUri);
        Assert.Equal("https://app.example.com", model.ClientUriSan);
        Assert.Equal(5, model.CommunityId);
        Assert.True(model.Enabled);
        Assert.Equal("https://idp.example.com/token", model.TokenEndpoint);
    }

    [Fact]
    public void ToModel_NullEntity_ReturnsEmptyModel()
    {
        TieredClientEntity? entity = null;

        var model = entity.ToModel();

        Assert.NotNull(model);
        Assert.Equal(0, model.Id);
        Assert.Null(model.ClientName);
        Assert.Null(model.ClientId);
    }

    [Fact]
    public void ToEntity_MapsAllProperties()
    {
        var model = new TieredClientModel
        {
            Id = 2,
            ClientName = "My Client",
            ClientId = "client-456",
            IdPBaseUrl = "https://idp2.example.com",
            RedirectUri = "https://app2.example.com/callback",
            ClientUriSan = "https://app2.example.com",
            CommunityId = 3,
            Enabled = false,
            TokenEndpoint = "https://idp2.example.com/token"
        };

        var entity = model.ToEntity();

        Assert.Equal(2, entity.Id);
        Assert.Equal("My Client", entity.ClientName);
        Assert.Equal("client-456", entity.ClientId);
        Assert.Equal("https://idp2.example.com", entity.IdPBaseUrl);
        Assert.Equal("https://app2.example.com/callback", entity.RedirectUri);
        Assert.Equal("https://app2.example.com", entity.ClientUriSan);
        Assert.Equal(3, entity.CommunityId);
        Assert.False(entity.Enabled);
        Assert.Equal("https://idp2.example.com/token", entity.TokenEndpoint);
    }

    [Fact]
    public void ToEntity_NullProperties_DefaultsToEmptyStrings()
    {
        var model = new TieredClientModel
        {
            Id = 1,
            ClientName = null,
            ClientId = null,
            IdPBaseUrl = null,
            RedirectUri = null,
            ClientUriSan = null,
            TokenEndpoint = null
        };

        var entity = model.ToEntity();

        Assert.Equal(string.Empty, entity.ClientName);
        Assert.Equal(string.Empty, entity.ClientId);
        Assert.Equal(string.Empty, entity.IdPBaseUrl);
        Assert.Equal(string.Empty, entity.RedirectUri);
        Assert.Equal(string.Empty, entity.ClientUriSan);
        Assert.Equal(string.Empty, entity.TokenEndpoint);
    }

    [Fact]
    public void RoundTrip_EntityToModelToEntity_PreservesValues()
    {
        var original = new TieredClientEntity
        {
            Id = 9,
            ClientName = "Roundtrip Client",
            ClientId = "rt-client",
            IdPBaseUrl = "https://rt.example.com",
            RedirectUri = "https://rt.example.com/cb",
            ClientUriSan = "https://rt.example.com",
            CommunityId = 2,
            Enabled = true,
            TokenEndpoint = "https://rt.example.com/token"
        };

        var roundTripped = original.ToModel().ToEntity();

        Assert.Equal(original.Id, roundTripped.Id);
        Assert.Equal(original.ClientName, roundTripped.ClientName);
        Assert.Equal(original.ClientId, roundTripped.ClientId);
        Assert.Equal(original.IdPBaseUrl, roundTripped.IdPBaseUrl);
        Assert.Equal(original.RedirectUri, roundTripped.RedirectUri);
        Assert.Equal(original.ClientUriSan, roundTripped.ClientUriSan);
        Assert.Equal(original.CommunityId, roundTripped.CommunityId);
        Assert.Equal(original.Enabled, roundTripped.Enabled);
        Assert.Equal(original.TokenEndpoint, roundTripped.TokenEndpoint);
    }
}

public class AnchorMapperTests
{
    private static string GetTestCertPem()
    {
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/caLocalhostCert.cer");
        return cert.ExportCertificatePem();
    }

    private static X509Certificate2 GetTestCert()
    {
        return X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/caLocalhostCert.cer");
    }

    [Fact]
    public void ToModel_MapsAllProperties()
    {
        var cert = GetTestCert();
        var pem = cert.ExportCertificatePem();

        var entity = new AnchorEntity
        {
            Id = 1,
            Enabled = true,
            Name = "Test Anchor",
            X509Certificate = pem,
            Thumbprint = cert.Thumbprint,
            BeginDate = cert.NotBefore,
            EndDate = cert.NotAfter,
            CommunityId = 5,
            Community = new CommunityEntity { Id = 5, Name = "udap://test" }
        };

        var model = entity.ToModel();

        Assert.Equal(1, model.Id);
        Assert.True(model.Enabled);
        Assert.Equal("Test Anchor", model.Name);
        Assert.Equal(5, model.CommunityId);
        Assert.Equal("udap://test", model.Community);
        Assert.Equal(pem, model.Certificate);
    }

    [Fact]
    public void ToModel_NullCommunity_MapsCommunityNameAsNull()
    {
        var pem = GetTestCertPem();

        var entity = new AnchorEntity
        {
            Id = 2,
            Name = "No Community",
            X509Certificate = pem,
            Community = null,
            CommunityId = 0
        };

        var model = entity.ToModel();

        Assert.Null(model.Community);
    }

    [Fact]
    public void ToModel_NullIntermediates_MapsAsNull()
    {
        var pem = GetTestCertPem();

        var entity = new AnchorEntity
        {
            Id = 3,
            Name = "No Intermediates",
            X509Certificate = pem,
            Intermediates = null
        };

        var model = entity.ToModel();

        Assert.Null(model.Intermediates);
    }

    [Fact]
    public void ToModel_WithIntermediates_MapsIntermediates()
    {
        var pem = GetTestCertPem();

        var entity = new AnchorEntity
        {
            Id = 4,
            Name = "With Intermediates",
            X509Certificate = pem,
            Intermediates = new List<IntermediateEntity>
            {
                new()
                {
                    Id = 10,
                    AnchorId = 4,
                    Enabled = true,
                    Name = "Intermediate 1",
                    X509Certificate = pem,
                    Thumbprint = "ABC123"
                }
            }
        };

        var model = entity.ToModel();

        Assert.NotNull(model.Intermediates);
        Assert.Single(model.Intermediates);
        Assert.Equal("Intermediate 1", model.Intermediates.First().Name);
    }

    [Fact]
    public void ToModel_HandlesPemWithHeaders()
    {
        var cert = GetTestCert();
        var pemWithHeaders = "-----BEGIN CERTIFICATE-----\n" +
                             Convert.ToBase64String(cert.RawData) +
                             "\n-----END CERTIFICATE-----";

        var entity = new AnchorEntity
        {
            Id = 5,
            Name = "PEM Headers",
            X509Certificate = pemWithHeaders,
            CommunityId = 1
        };

        var model = entity.ToModel();

        Assert.NotNull(model);
        Assert.Equal("PEM Headers", model.Name);
    }

    [Fact]
    public void ToEntity_MapsAllProperties()
    {
        var cert = GetTestCert();

        var model = new AnchorModel(cert, "udap://test", "Test Anchor")
        {
            Id = 1,
            Enabled = true,
            CommunityId = 5
        };

        var entity = model.ToEntity();

        Assert.Equal(1, entity.Id);
        Assert.True(entity.Enabled);
        Assert.Equal("Test Anchor", entity.Name);
        Assert.Equal(cert.Thumbprint, entity.Thumbprint);
        Assert.Equal(5, entity.CommunityId);
        Assert.Equal(cert.NotBefore, entity.BeginDate);
        Assert.Equal(cert.NotAfter, entity.EndDate);
    }

    [Fact]
    public void ToEntity_NullIntermediates_DefaultsToEmptyList()
    {
        var cert = GetTestCert();

        var model = new AnchorModel(cert)
        {
            Id = 2,
            CommunityId = 1,
            Intermediates = null
        };

        var entity = model.ToEntity();

        Assert.NotNull(entity.Intermediates);
        Assert.Empty(entity.Intermediates);
    }
}

public class IntermediateCertificateMapperTests
{
    private static string GetTestCertPem()
    {
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/caLocalhostCert.cer");
        return cert.ExportCertificatePem();
    }

    private static X509Certificate2 GetTestCert()
    {
        return X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/caLocalhostCert.cer");
    }

    [Fact]
    public void ToModel_MapsAllProperties()
    {
        var cert = GetTestCert();
        var pem = cert.ExportCertificatePem();

        var entity = new IntermediateEntity
        {
            Id = 1,
            AnchorId = 5,
            Enabled = true,
            Name = "Test Intermediate",
            X509Certificate = pem,
            Thumbprint = cert.Thumbprint,
            BeginDate = cert.NotBefore,
            EndDate = cert.NotAfter
        };

        var model = entity.ToModel();

        Assert.Equal(1, model.Id);
        Assert.Equal(5, model.AnchorId);
        Assert.True(model.Enabled);
        Assert.Equal("Test Intermediate", model.Name);
        Assert.Equal(pem, model.Certificate);
    }

    [Fact]
    public void ToModel_HandlesPemWithHeaders()
    {
        var cert = GetTestCert();
        var pemWithHeaders = "-----BEGIN CERTIFICATE-----\n" +
                             Convert.ToBase64String(cert.RawData) +
                             "\n-----END CERTIFICATE-----";

        var entity = new IntermediateEntity
        {
            Id = 2,
            AnchorId = 1,
            Name = "PEM Headers",
            X509Certificate = pemWithHeaders
        };

        var model = entity.ToModel();

        Assert.NotNull(model);
        Assert.Equal("PEM Headers", model.Name);
    }

    [Fact]
    public void ToEntity_MapsAllProperties()
    {
        var cert = GetTestCert();

        var model = new IntermediateModel(cert, "Test Intermediate")
        {
            Id = 3,
            AnchorId = 7,
            Enabled = true
        };

        var entity = model.ToEntity();

        Assert.Equal(3, entity.Id);
        Assert.Equal(7, entity.AnchorId);
        Assert.True(entity.Enabled);
        Assert.Equal("Test Intermediate", entity.Name);
        Assert.Equal(cert.Thumbprint, entity.Thumbprint);
        Assert.Equal(cert.NotBefore, entity.BeginDate);
        Assert.Equal(cert.NotAfter, entity.EndDate);
    }

    [Fact]
    public void RoundTrip_EntityToModelToEntity_PreservesValues()
    {
        var cert = GetTestCert();
        var pem = cert.ExportCertificatePem();

        var original = new IntermediateEntity
        {
            Id = 4,
            AnchorId = 2,
            Enabled = true,
            Name = "Roundtrip",
            X509Certificate = pem,
            Thumbprint = cert.Thumbprint,
            BeginDate = cert.NotBefore,
            EndDate = cert.NotAfter
        };

        var roundTripped = original.ToModel().ToEntity();

        Assert.Equal(original.Id, roundTripped.Id);
        Assert.Equal(original.AnchorId, roundTripped.AnchorId);
        Assert.Equal(original.Enabled, roundTripped.Enabled);
        Assert.Equal(original.Name, roundTripped.Name);
        Assert.Equal(original.Thumbprint, roundTripped.Thumbprint);
        Assert.Equal(original.BeginDate, roundTripped.BeginDate);
        Assert.Equal(original.EndDate, roundTripped.EndDate);
    }
}
