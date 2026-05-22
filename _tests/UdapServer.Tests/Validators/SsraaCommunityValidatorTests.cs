#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Storage.Stores;
using Udap.Server.Validation;
using Udap.Server.Validation.Default;
using Udap.Ssraa.Server;

namespace UdapServer.Tests.Validators;

public class SsraaCommunityValidatorTests
{
    private readonly ILogger<DefaultUdapAuthorizationExtensionValidator> _logger =
        Substitute.For<ILogger<DefaultUdapAuthorizationExtensionValidator>>();

    #region AddUdapSsraaValidation DI Registration

    [Fact]
    public void AddUdapSsraaValidation_RegistersTokenValidator()
    {
        var services = new ServiceCollection();

        services.AddUdapSsraaValidation(options =>
        {
            options.Communities.Add("udap://fhirlabs.net");
        });

        var provider = services.BuildServiceProvider();
        var validator = provider.GetService<ICommunityTokenValidator>();

        Assert.NotNull(validator);
        Assert.IsType<SsraaTokenValidator>(validator);
    }

    [Fact]
    public void AddUdapSsraaValidation_ConfiguresOptions()
    {
        var services = new ServiceCollection();

        services.AddUdapSsraaValidation(options =>
        {
            options.Communities.Add("udap://fhirlabs.net");
            options.Communities.Add("udap://other-community");
        });

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<SsraaValidationOptions>>();

        Assert.Contains("udap://fhirlabs.net", options.Value.Communities);
        Assert.Contains("udap://other-community", options.Value.Communities);
    }

    [Fact]
    public void AddUdapSsraaValidation_DefaultOverload_RegistersWithEmptyOptions()
    {
        var services = new ServiceCollection();

        services.AddUdapSsraaValidation();

        var provider = services.BuildServiceProvider();
        var validator = provider.GetService<ICommunityTokenValidator>();
        var options = provider.GetRequiredService<IOptions<SsraaValidationOptions>>();

        Assert.NotNull(validator);
        Assert.Empty(options.Value.Communities);
    }

    [Fact]
    public void AddUdapSsraaValidation_OptionsHaveCorrectDefaults()
    {
        var services = new ServiceCollection();

        services.AddUdapSsraaValidation();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<SsraaValidationOptions>>();

        Assert.NotNull(options.Value.ClientCredentialsExtensionsRequired);
        Assert.Contains(UdapConstants.UdapAuthorizationExtensions.Hl7B2B,
            options.Value.ClientCredentialsExtensionsRequired!);
        Assert.Null(options.Value.AuthorizationCodeExtensionsRequired);
    }

    #endregion

    #region SsraaTokenValidator Unit Tests

    [Fact]
    public void AppliesToCommunity_ConfiguredCommunity_ReturnsTrue()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        Assert.True(validator.AppliesToCommunity("udap://fhirlabs.net"));
    }

    [Fact]
    public void AppliesToCommunity_UnconfiguredCommunity_ReturnsFalse()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        Assert.False(validator.AppliesToCommunity("udap://other-community"));
    }

    [Fact]
    public void GetValidationRules_ClientCredentials_RequiresHl7B2B()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        var rules = validator.GetValidationRules("client_credentials");

        Assert.NotNull(rules);
        Assert.NotNull(rules.RequiredExtensions);
        Assert.Contains(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, rules.RequiredExtensions);
    }

    [Fact]
    public void GetValidationRules_AuthorizationCode_NoExtensionsRequired()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        var rules = validator.GetValidationRules("authorization_code");

        Assert.NotNull(rules);
        Assert.Null(rules.RequiredExtensions);
    }

    [Fact]
    public void GetValidationRules_AllHl7V3PurposeOfUseCodesPresent()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        var rules = validator.GetValidationRules("client_credentials");

        Assert.NotNull(rules?.AllowedPurposeOfUse);
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#TREAT", rules.AllowedPurposeOfUse);
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#ETREAT", rules.AllowedPurposeOfUse);
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#BTG", rules.AllowedPurposeOfUse);
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#HPAYMT", rules.AllowedPurposeOfUse);
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#PUBHLTH", rules.AllowedPurposeOfUse);
        Assert.Contains("urn:oid:2.16.840.1.113883.5.8#HMARKT", rules.AllowedPurposeOfUse);
        // Should have all 62 codes
        Assert.Equal(62, rules.AllowedPurposeOfUse.Count);
    }

    [Fact]
    public void GetValidationRules_NoMaxPurposeOfUseCount()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        var rules = validator.GetValidationRules("client_credentials");

        Assert.NotNull(rules);
        Assert.Null(rules.MaxPurposeOfUseCount);
    }

    [Fact]
    public void GetValidationRules_UnknownGrantType_ReturnsNullRequiredExtensions()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        var rules = validator.GetValidationRules("device_code");

        Assert.NotNull(rules);
        Assert.Null(rules.RequiredExtensions);
    }

    [Fact]
    public void GetValidationRules_NullGrantType_ReturnsNullRequiredExtensions()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        var rules = validator.GetValidationRules(null);

        Assert.NotNull(rules);
        Assert.Null(rules.RequiredExtensions);
    }

    [Fact]
    public void GetValidationRules_TefcaXpCode_NotInAllowedSet()
    {
        var validator = CreateSsraaValidator("udap://fhirlabs.net");

        var rules = validator.GetValidationRules("client_credentials");

        Assert.NotNull(rules?.AllowedPurposeOfUse);
        // TEFCA XP codes use a different OID and should NOT be in the SSRAA allowed set
        Assert.DoesNotContain("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT", rules.AllowedPurposeOfUse);
        Assert.DoesNotContain("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#Joe", rules.AllowedPurposeOfUse);
    }

    #endregion

    #region Integration with DefaultUdapAuthorizationExtensionValidator

    [Fact]
    public async Task SsraaCommunity_TefcaXpCode_IsRejected()
    {
        // Reproduces: client_credentials token request to SSRAA community with
        // purpose_of_use "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#Joe"
        // This is a TEFCA OID, not an HL7 v3 PurposeOfUse code, and must be rejected.
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://fhirlabs.net"));

        var ssraaValidator = CreateSsraaValidator("udap://fhirlabs.net");
        var validator = CreateBaseValidator(clientStore, [ssraaValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99",
            OrganizationName = "FhirLabs"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#Joe");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("disallowed", result.ErrorDescription);
        Assert.Contains("Joe", result.ErrorDescription);
    }

    [Fact]
    public async Task SsraaCommunity_ValidHl7V3Code_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://fhirlabs.net"));

        var ssraaValidator = CreateSsraaValidator("udap://fhirlabs.net");
        var validator = CreateBaseValidator(clientStore, [ssraaValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99",
            OrganizationName = "FhirLabs"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task SsraaCommunity_BogusCode_IsRejected()
    {
        // Any arbitrary string that isn't in the HL7 v3 value set should be rejected
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://fhirlabs.net"));

        var ssraaValidator = CreateSsraaValidator("udap://fhirlabs.net");
        var validator = CreateBaseValidator(clientStore, [ssraaValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99",
            OrganizationName = "FhirLabs"
        };
        b2b.PurposeOfUse!.Add("TOTALLY-MADE-UP");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("disallowed", result.ErrorDescription);
    }

    [Fact]
    public async Task SsraaCommunity_MultipleValidCodes_Succeeds()
    {
        // SSRAA does not limit purpose_of_use count (MaxPurposeOfUseCount is null)
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://fhirlabs.net"));

        var ssraaValidator = CreateSsraaValidator("udap://fhirlabs.net");
        var validator = CreateBaseValidator(clientStore, [ssraaValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99",
            OrganizationName = "FhirLabs"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#ETREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#HPAYMT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region ICommunityTokenValidator default interface method

    [Fact]
    public void GetValidationRules_DefaultImplementation_ReturnsNull()
    {
        ICommunityTokenValidator validator = new MinimalCommunityTokenValidator();

        var rules = validator.GetValidationRules("client_credentials");

        Assert.Null(rules);
    }

    [Fact]
    public void GetValidationRules_DefaultImplementation_ReturnsNullForNullGrantType()
    {
        ICommunityTokenValidator validator = new MinimalCommunityTokenValidator();

        var rules = validator.GetValidationRules(null);

        Assert.Null(rules);
    }

    #endregion

    #region Helpers

    private class MinimalCommunityTokenValidator : ICommunityTokenValidator
    {
        public bool AppliesToCommunity(string communityName) => false;

        public Task<AuthorizationExtensionValidationResult> ValidateAsync(
            UdapAuthorizationExtensionValidationContext context)
            => Task.FromResult(AuthorizationExtensionValidationResult.Success());
    }


    private static SsraaTokenValidator CreateSsraaValidator(params string[] communities)
    {
        var options = new SsraaValidationOptions();
        foreach (var c in communities) options.Communities.Add(c);
        return new SsraaTokenValidator(Options.Create(options));
    }

    private DefaultUdapAuthorizationExtensionValidator CreateBaseValidator(
        IUdapClientRegistrationStore clientStore,
        IEnumerable<ICommunityTokenValidator> communityValidators)
    {
        return new DefaultUdapAuthorizationExtensionValidator(
            clientStore, communityValidators, _logger);
    }

    private static UdapAuthorizationExtensionValidationContext CreateContext(
        string? communityId = null,
        Dictionary<string, object>? extensions = null,
        string clientId = "test-client",
        string grantType = "client_credentials")
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(
            handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = clientId,
                Claims = new Dictionary<string, object> { ["sub"] = clientId }
            }));

        return new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwt,
            ClientId = clientId,
            Extensions = extensions,
            CommunityId = communityId,
            GrantType = grantType
        };
    }

    #endregion
}
