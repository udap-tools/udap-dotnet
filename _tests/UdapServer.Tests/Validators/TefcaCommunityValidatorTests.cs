#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Registration;
using Udap.Server.Validation;
using Udap.Tefca.Model;
using Udap.Tefca.Server;
using Xunit;

namespace UdapServer.Tests.Validators;

public class TefcaCommunityValidatorTests
{
    private static readonly IOptions<TefcaValidationOptions> DefaultOptions =
        Options.Create(new TefcaValidationOptions());

    #region AddUdapTefcaValidation DI Registration

    [Fact]
    public void AddUdapTefcaValidation_RegistersTokenValidator()
    {
        var services = new ServiceCollection();

        services.AddUdapTefcaValidation();

        var provider = services.BuildServiceProvider();
        var validator = provider.GetService<ICommunityTokenValidator>();

        Assert.NotNull(validator);
        Assert.IsType<TefcaTokenValidator>(validator);
    }

    [Fact]
    public void AddUdapTefcaValidation_RegistersRegistrationValidator()
    {
        var services = new ServiceCollection();

        services.AddUdapTefcaValidation();

        var provider = services.BuildServiceProvider();
        var validator = provider.GetService<ICommunityRegistrationValidator>();

        Assert.NotNull(validator);
        Assert.IsType<TefcaRegistrationValidator>(validator);
    }

    [Fact]
    public void AddUdapTefcaValidation_ConfiguresOptions()
    {
        var services = new ServiceCollection();

        services.AddUdapTefcaValidation(options =>
        {
            options.Communities.Add("tefca://test-community");
        });

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<TefcaValidationOptions>>();

        Assert.Contains("tefca://test-community", options.Value.Communities);
    }

    [Fact]
    public void AddUdapTefcaValidation_DefaultOverload_RegistersWithDefaultCommunity()
    {
        var services = new ServiceCollection();

        services.AddUdapTefcaValidation();

        var provider = services.BuildServiceProvider();
        var validator = provider.GetService<ICommunityTokenValidator>();
        var regValidator = provider.GetService<ICommunityRegistrationValidator>();
        var options = provider.GetRequiredService<IOptions<TefcaValidationOptions>>();

        Assert.NotNull(validator);
        Assert.NotNull(regValidator);
        Assert.Contains(TefcaConstants.CommunityUri, options.Value.Communities);
    }

    #endregion

    #region TefcaRegistrationValidator

    [Theory]
    [InlineData("T-TRTMNT")]
    [InlineData("T-TREAT")]
    [InlineData("T-PYMNT")]
    [InlineData("T-HCO")]
    [InlineData("T-HCO-CC")]
    [InlineData("T-HCO-HED")]
    [InlineData("T-HCO-QM")]
    [InlineData("T-PH")]
    [InlineData("T-PH-ECR")]
    [InlineData("T-PH-ELR")]
    [InlineData("T-IAS")]
    [InlineData("T-GOVDTRM")]
    public async Task Registration_ValidExchangePurpose_Succeeds(string xpCode)
    {
        var validator = new TefcaRegistrationValidator(DefaultOptions);
        var context = CreateRegistrationContext($"urn:oid:2.999#{xpCode}");

        var result = await validator.ValidateAsync(context);

        Assert.Null(result); // null = success
    }

    [Fact]
    public async Task Registration_InvalidExchangePurpose_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(DefaultOptions);
        var context = CreateRegistrationContext("urn:oid:2.999#INVALID");

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Contains("INVALID", result.ErrorDescription);
    }

    [Fact]
    public async Task Registration_SanUriWithoutFragment_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(DefaultOptions);
        var context = CreateRegistrationContext("urn:oid:2.999");

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Contains("exchange purpose code after '#'", result.ErrorDescription);
    }

    [Fact]
    public async Task Registration_EmptyIssuer_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(DefaultOptions);
        var context = CreateRegistrationContext(null);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
    }

    [Fact]
    public async Task Registration_TrailingHash_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(DefaultOptions);
        var context = CreateRegistrationContext("urn:oid:2.999#");

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
    }

    [Fact]
    public void Registration_AppliesToTefcaCommunity()
    {
        var validator = new TefcaRegistrationValidator(DefaultOptions);

        Assert.True(validator.AppliesToCommunity(TefcaConstants.CommunityUri));
        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
        Assert.False(validator.AppliesToCommunity("udap://Provider2"));
    }

    #endregion

    #region TefcaTokenValidator

    [Fact]
    public async Task Token_MatchingPurposeOfUse_Succeeds()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TREAT",
            purposeOfUse: $"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-TREAT");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_MatchingPurposeOfUse_BareCode_Succeeds()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TRTMNT",
            purposeOfUse: "T-TRTMNT");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_MismatchedPurposeOfUse_IsRejected()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TREAT",
            purposeOfUse: $"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-PYMNT");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("T-PYMNT", result.ErrorDescription);
        Assert.Contains("T-TREAT", result.ErrorDescription);
    }

    [Fact]
    public async Task Token_NoRegisteredSanUri_IsRejected()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: null,
            purposeOfUse: "T-TREAT");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
    }

    [Fact]
    public async Task Token_SanUriWithoutFragment_IsRejected()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999",
            purposeOfUse: "T-TREAT");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Token_NoExtensions_Succeeds()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TREAT",
            purposeOfUse: null); // no extensions at all

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Token_AppliesToTefcaCommunity()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);

        Assert.True(validator.AppliesToCommunity(TefcaConstants.CommunityUri));
        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
    }

    [Fact]
    public void GetValidationRules_ClientCredentials_RequiresHl7B2B()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);

        var rules = validator.GetValidationRules("client_credentials");

        Assert.NotNull(rules);
        Assert.NotNull(rules.RequiredExtensions);
        Assert.Contains(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, rules.RequiredExtensions);
        Assert.Equal(1, rules.MaxPurposeOfUseCount);
    }

    [Fact]
    public void GetValidationRules_AuthorizationCode_NoExtensionsRequired()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);

        var rules = validator.GetValidationRules("authorization_code");

        Assert.NotNull(rules);
        Assert.NotNull(rules.RequiredExtensions);
        Assert.Empty(rules.RequiredExtensions);
        Assert.Equal(1, rules.MaxPurposeOfUseCount);
    }

    [Fact]
    public void GetValidationRules_UnknownGrantType_ReturnsNullRequiredExtensions()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);

        var rules = validator.GetValidationRules("device_code");

        Assert.NotNull(rules);
        Assert.Null(rules.RequiredExtensions);
    }

    [Fact]
    public void GetValidationRules_NullGrantType_ReturnsNullRequiredExtensions()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);

        var rules = validator.GetValidationRules(null);

        Assert.NotNull(rules);
        Assert.Null(rules.RequiredExtensions);
    }

    [Fact]
    public void GetValidationRules_AllTefcaXpCodesPresent()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);

        var rules = validator.GetValidationRules("client_credentials");

        Assert.NotNull(rules?.AllowedPurposeOfUse);
        Assert.Equal(12, rules.AllowedPurposeOfUse.Count);
        Assert.Contains($"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-TREAT", rules.AllowedPurposeOfUse);
        Assert.Contains($"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-IAS", rules.AllowedPurposeOfUse);
    }

    #endregion

    #region Regression — non-TEFCA communities

    [Fact]
    public void Registration_NonTefcaCommunity_NotApplicable()
    {
        var validator = new TefcaRegistrationValidator(DefaultOptions);

        // Validator should not apply, so it would never be called
        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
    }

    [Fact]
    public void Token_NonTefcaCommunity_NotApplicable()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);

        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
    }

    #endregion

    #region TefcaIAS conditional requirement

    [Fact]
    public async Task Token_IAS_ClientCredentials_WithTefcaIas_Succeeds()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-IAS",
            purposeOfUse: "T-IAS",
            grantType: "client_credentials",
            includeTefcaIas: true);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_IAS_ClientCredentials_WithoutTefcaIas_IsRejected()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-IAS",
            purposeOfUse: "T-IAS",
            grantType: "client_credentials",
            includeTefcaIas: false);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("tefca_ias", result.ErrorDescription);
    }

    [Fact]
    public async Task Token_IAS_AuthorizationCode_WithoutTefcaIas_Succeeds()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-IAS",
            purposeOfUse: "T-IAS",
            grantType: "authorization_code",
            includeTefcaIas: false);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_NonIAS_ClientCredentials_WithoutTefcaIas_Succeeds()
    {
        var validator = new TefcaTokenValidator(DefaultOptions);
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TREAT",
            purposeOfUse: "T-TREAT",
            grantType: "client_credentials",
            includeTefcaIas: false);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region Helpers

    private static UdapDynamicClientRegistrationContext CreateRegistrationContext(string? issuer)
    {
        return new UdapDynamicClientRegistrationContext
        {
            Request = new UdapRegisterRequest(),
            Issuer = issuer,
            CommunityName = TefcaConstants.CommunityUri
        };
    }

    private static UdapAuthorizationExtensionValidationContext CreateTokenContext(
        string? sanUri,
        string? purposeOfUse,
        string grantType = "client_credentials",
        bool includeTefcaIas = false)
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(
            handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "test-client",
                Claims = new Dictionary<string, object> { ["sub"] = "test-client" }
            }));

        Dictionary<string, object>? extensions = null;

        if (purposeOfUse != null)
        {
            var b2b = new HL7B2BAuthorizationExtension
            {
                OrganizationId = "Organization/1.2.3",
                OrganizationName = "Test Org"
            };
            b2b.PurposeOfUse!.Add(purposeOfUse);

            extensions = new Dictionary<string, object>
            {
                [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
            };

            if (includeTefcaIas)
            {
                extensions[TefcaConstants.UdapAuthorizationExtensions.TEFCAIAS] =
                    new TEFCAIASAuthorizationExtension();
            }
        }

        return new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwt,
            ClientId = "test-client",
            Extensions = extensions,
            CommunityId = "1",
            CommunityName = TefcaConstants.CommunityUri,
            GrantType = grantType,
            SanUri = sanUri
        };
    }

    #endregion
}
