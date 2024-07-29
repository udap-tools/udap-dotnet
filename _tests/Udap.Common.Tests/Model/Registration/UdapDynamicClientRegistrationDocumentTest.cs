#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;

namespace Udap.Common.Tests.Model.Registration;
public class UdapDynamicClientRegistrationDocumentTest
{

    [Fact]
    public void ClientCredentialsFlowTest()
    {
        var expiration = TimeSpan.FromMinutes(5);
        var expirationEpochTime = EpochTime.GetIntDate(DateTime.Now.Add(expiration));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");
        
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .Build();

        document.AddClaims(new Claim[] { new("MyClaim", "Testing 123") });

        document.ClientId.Should().BeNull();
        document.Audience.Should().Be("https://securedcontrols.net/connect/register");
        document.Expiration.Should().BeCloseTo(expirationEpochTime, 3);
        document.JwtId.Should().NotBeNullOrWhiteSpace();
        document.ClientName.Should().Be("dotnet system test client");
        document.Contacts!.Count.Should().Be(2);
        document.Contacts.Should().Contain("mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com");
        document.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        document.Scope.Should().Be("system/Patient.rs system/Practitioner.read");
        document.LogoUri.Should().Be("https://avatars.githubusercontent.com/u/77421324?s=48&v=4");
        document.ResponseTypes.Should().BeEmpty();
        document.GrantTypes!.Count.Should().Be(1);
        document.GrantTypes.Should().Contain("client_credentials");

        var iat = EpochTime.DateTime(document.IssuedAt).ToUniversalTime();


        document.ClientId = "MyNewClientId"; // Simulate successful registration
        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        documentDeserialize!.ClientId.Should().Be(document.ClientId);
        documentDeserialize.Should().NotBeNullOrEmpty();
        documentDeserialize.Audience.Should().Be(document.Audience);
        documentDeserialize.Expiration.Should().Be(document.Expiration);
        documentDeserialize.JwtId.Should().Be(document.JwtId);
        documentDeserialize.ClientName.Should().Be(document.ClientName);
        documentDeserialize.Contacts.Should().Contain(document.Contacts);
        documentDeserialize.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        documentDeserialize.Scope.Should().Be(document.Scope);
        documentDeserialize.LogoUri.Should().Be(document.LogoUri);
        documentDeserialize.GrantTypes!.Count.Should().Be(1);
        documentDeserialize.SoftwareStatement.Should().Be(document.SoftwareStatement); //echo back software statement
        documentDeserialize.ResponseTypes.Should().BeEmpty();
        documentDeserialize["MyClaim"].ToString().Should().Be("Testing 123");
        documentDeserialize.IssuedAt.Should().Be(EpochTime.GetIntDate(iat));


        // Extra property coverage details
        document.Contacts = null;
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        documentDeserialize!.Contacts.Should().BeEmpty();

        //
        // Empty logo and software statement test.  Some upstream builders pass an empty logo because it is not required by client_credentials
        //
        Action buildSoftwareStatement = () => UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("")
            .BuildSoftwareStatement();

        buildSoftwareStatement.Should().NotThrow();


        Action buildSoftwareStatementRS384 = () => UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("")
            .BuildSoftwareStatement();

        buildSoftwareStatementRS384.Should().NotThrow();

    }

    [Fact]
    public void CancelRegistrationClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithLogoUri("")
        .Build();

        document.GrantTypes.Should().BeEmpty();
    }

    [Fact]
    public void CancelRegistrationAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Cancel(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .Build();

        document.GrantTypes.Should().BeEmpty();
    }

    /// <summary>
    /// Pick another issuer that matches a SAN other than the first one in the Certificate
    /// </summary>
    [Fact]
    public void AlternateSanClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
        .Build();

        document.Issuer.Should().Be("https://fhirlabs.net:7016/fhir/r4");

        Action act = () => UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/not_here"));

        act.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Certificate does not contain a URI Subject Alternative Name of, https://fhirlabs.net:7016/fhir/not_here"));

    }

    [Fact]
    public void ControlTimesClientCredentialsTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var issuedAt = EpochTime.GetIntDate(DateTime.Now);
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithExpiration(expiration)
            .WithIssuedAt(issuedAt)
            .Build();

        document.IssuedAt.Should().Be(issuedAt);
        document.Expiration.Should().Be(expiration);

    }

    [Fact]
    public void ControlTimesAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var issuedAt = EpochTime.GetIntDate(DateTime.Now);
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithExpiration(expiration)
            .WithIssuedAt(issuedAt)
            .Build();

        document.IssuedAt.Should().Be(issuedAt);
        document.Expiration.Should().Be(expiration);

    }

    /// <summary>
    /// Pick another issuer that matches a SAN other than the first one in the Certificate
    /// </summary>
    [Fact]
    public void AlternateSanAuthorizationCodeFlowTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .Build();

        document.Issuer.Should().Be("https://fhirlabs.net:7016/fhir/r4");

        Action act = () => UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/not_here"));

        act.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Certificate does not contain a URI Subject Alternative Name of, https://fhirlabs.net:7016/fhir/not_here"));
    }


    [Fact]
    public void AuthorizationCodeFlowTest()
    {
        var expiration = TimeSpan.FromMinutes(5);
        var expirationEpochTime = EpochTime.GetIntDate(DateTime.Now.Add(expiration));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .Build();

        document.AddClaims(new Claim[] { new Claim("MyClaim", "Testing 123") });

        document.ClientId.Should().BeNull();
        document.Audience.Should().Be("https://securedcontrols.net/connect/register");
        document.Expiration.Should().BeCloseTo(expirationEpochTime, 3);
        document.JwtId.Should().NotBeNullOrWhiteSpace();
        document.ClientName.Should().Be("dotnet system test client");
        document.Contacts!.Count.Should().Be(2);
        document.Contacts.Should().Contain("mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com");
        document.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        document.Scope.Should().Be("system/Patient.rs system/Practitioner.read");
        document.ResponseTypes.Should().Contain("code");
        document.Issuer.Should().Be("https://fhirlabs.net/fhir/r4"); // same as first subject alternative name
        document.RedirectUris!.Count.Should().Be(1);
        document.RedirectUris.Should().Contain("https://client.fhirlabs.net/redirect/");
        document.LogoUri.Should().Be("https://avatars.githubusercontent.com/u/77421324?s=48&v=4");
        document.GrantTypes!.Count.Should().Be(1);
        document.GrantTypes.Should().Contain("authorization_code");

        var signedDocument = SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(clientCert, document).Build();

        document.SoftwareStatement = signedDocument;
        document.ClientId = "MyNewClientId"; // Simulate successful registration
        var serializeDocument = JsonSerializer.Serialize(document);
        var documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);

        documentDeserialize!.ClientId.Should().Be(document.ClientId);
        documentDeserialize.Should().NotBeNullOrEmpty();
        documentDeserialize.Audience.Should().Be(document.Audience);
        documentDeserialize.Expiration.Should().Be(document.Expiration);
        documentDeserialize.JwtId.Should().Be(document.JwtId);
        documentDeserialize.ClientName.Should().Be(document.ClientName);
        documentDeserialize.Contacts.Should().ContainInOrder(document.Contacts);
        documentDeserialize.TokenEndpointAuthMethod.Should().Be(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue);
        documentDeserialize.Scope.Should().Be(document.Scope);
        documentDeserialize.SoftwareStatement.Should().NotBeNullOrWhiteSpace();
        documentDeserialize.SoftwareStatement.Should().Be(document.SoftwareStatement); //echo back software statement
        documentDeserialize.ResponseTypes.Should().ContainInOrder(document.ResponseTypes);
        documentDeserialize.Issuer.Should().Be(document.Issuer);
        documentDeserialize.RedirectUris.Should().ContainInOrder(document.RedirectUris);
        documentDeserialize.LogoUri.Should().Be(document.LogoUri);
        documentDeserialize.GrantTypes!.Count.Should().Be(1);
        documentDeserialize.GrantTypes.Should().Contain(document.GrantTypes);
        documentDeserialize["MyClaim"].ToString().Should().Be("Testing 123");

        // Extra property coverage details
        document.Contacts = null;
        document.ResponseTypes = null;
        document.GrantTypes = null;
        serializeDocument = JsonSerializer.Serialize(document);
        documentDeserialize = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(serializeDocument);
        documentDeserialize!.Contacts.Should().BeEmpty();
        documentDeserialize.ResponseTypes.Should().BeEmpty();
        documentDeserialize.GrantTypes.Should().BeEmpty();

        // What might happen on responding from Server
        var _ = new UdapDynamicClientRegistrationDocument()
        {
            ClientId = document.ClientId,
            SoftwareStatement = document.SoftwareStatement
        };

        Action act = () => new UdapDynamicClientRegistrationDocument()
        {
            ClientId = document.ClientId,
            SoftwareStatement = null
        };

        act.Should().NotThrow();


        Action buildSoftwareStatement = () => UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .BuildSoftwareStatement();

        buildSoftwareStatement.Should().NotThrow();

        Action buildSoftwareStatementRS384 = () => UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .BuildSoftwareStatement(UdapConstants.SupportedAlgorithm.RS384);

        buildSoftwareStatementRS384.Should().NotThrow();
    }


    [Fact]
    public void AuthorizationCodeFlowSetResponseTypeTest()
    {
        var expiration = EpochTime.GetIntDate(DateTime.Now.Add(TimeSpan.FromMinutes(5)));
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
        var clientCert = new X509Certificate2(cert, "udap-test");
        
        var documentAuthCode = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience("https://securedcontrols.net/connect/register")
            .WithExpiration(expiration)
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/").AbsoluteUri }!)
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithResponseTypes(new HashSet<string>(){"code", "secret"})
            .Build();

        documentAuthCode.ResponseTypes.Should().ContainInOrder(new HashSet<string>() { "code", "secret" });
    }

    [Fact]
    public void CertificateRequiredClientCredentials()
    {
        Action create = () => UdapDcrBuilderForClientCredentials
            .Create()
            .BuildSoftwareStatement();

        create.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));

        Action cancel = () => UdapDcrBuilderForClientCredentials
            .Cancel()
            .BuildSoftwareStatement();

        cancel.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));
    }

    [Fact]
    public void CertificateRequiredAuthorizationClodetest()
    {
        Action create = () => UdapDcrBuilderForAuthorizationCode
            .Create()
            .BuildSoftwareStatement();

        create.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));

        Action cancel = () => UdapDcrBuilderForAuthorizationCode
            .Cancel()
            .BuildSoftwareStatement();

        cancel.Should().Throw<Exception>()
            .Where(e => e.Message.StartsWith("Missing certificate"));
    }

}
