#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using NSubstitute;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Storage.Stores;
using Udap.Server.Validation;
using Udap.Server.Validation.Default;
using Udap.Tefca.Model;

namespace UdapServer.Tests.Validators;

public class DefaultUdapAuthorizationExtensionValidatorTests
{
    private readonly ILogger<DefaultUdapAuthorizationExtensionValidator> _logger =
        Substitute.For<ILogger<DefaultUdapAuthorizationExtensionValidator>>();

    #region No Community Validator — No Enforcement

    [Fact]
    public async Task NoCommunityValidator_NoExtensionsPresent_Succeeds()
    {
        var validator = CreateValidator();
        var context = CreateContext();

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NoCommunityValidator_ExtensionsPresent_Succeeds()
    {
        var validator = CreateValidator();
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NoCommunityValidator_AnyPOUCode_Succeeds()
    {
        // Without a community validator, no POU validation occurs
        var validator = CreateValidator();

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#ETREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#HPAYMT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region Required Extension Presence (via Community Validator)

    [Fact]
    public async Task CommunityValidator_RequiredExtension_Missing_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_RequiredExtension_NullExtensions_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: null);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("missing", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CommunityValidator_RequiredExtension_EmptyExtensions_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: new Dictionary<string, object>());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
    }

    [Fact]
    public async Task CommunityValidator_RequiredExtension_Present_Succeeds()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_MultipleRequiredExtensions_OneMissing_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions:
            [
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B,
                UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER
            ]);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_RequiredExtension_WrongKeyPresent_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    #endregion

    #region Structural Validation

    [Fact]
    public async Task B2BExtension_MissingOrganizationId_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = null
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("organization_id", result.ErrorDescription);
    }

    [Fact]
    public async Task B2BExtension_MissingPurposeOfUse_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        // PurposeOfUse is initialized to empty collection in constructor

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("purpose_of_use", result.ErrorDescription);
    }

    [Fact]
    public async Task B2BExtension_MissingVersion_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            Version = "",
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("version", result.ErrorDescription);
    }

    [Fact]
    public async Task B2BExtension_AllRequiredFieldsPresent_Succeeds()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task B2BUserExtension_MissingUserPerson_Fails()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]);

        var validator = CreateValidator(clientStore, [communityValidator]);

        var b2bUser = new HL7B2BUserAuthorizationExtension();
        b2bUser.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER] = b2bUser
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("user_person", result.ErrorDescription);
    }

    [Fact]
    public async Task UnknownExtensionType_NotStructurallyValidated_Succeeds()
    {
        var (clientStore, communityValidator) = SetupCommunityValidator(
            requiredExtensions: ["custom-extension"]);

        var validator = CreateValidator(clientStore, [communityValidator]);

        var extensions = new Dictionary<string, object>
        {
            ["custom-extension"] = new { version = "1", custom_field = "value" }
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region Community Settings

    [Fact]
    public async Task CommunityValidator_MatchingCommunity_UsesValidatorRules()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_MatchingCommunity_WithValidExtension_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_NonMatchingCommunity_NoEnforcement()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("2").Returns(Task.FromResult<string?>("udap://community-b"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-b").Returns(false);

        var validator = CreateValidator(clientStore, [communityValidator]);
        // No extensions — passes because no validator matched
        var context = CreateContext(communityId: "2");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_NullCommunityId_NoEnforcement()
    {
        var validator = CreateValidator();
        var context = CreateContext(communityId: null);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_RulesOverride_EmptyRequired_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string>() // empty — no extensions required
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_NullRules_NoEnforcement()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        // No extensions — passes because validator returned null rules
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_MultipleCommunities_CorrectOneSelected()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));
        clientStore.GetCommunityName("2").Returns(Task.FromResult<string?>("udap://community-b"));

        var validatorA = Substitute.For<ICommunityTokenValidator>();
        validatorA.AppliesToCommunity("udap://community-a").Returns(true);
        validatorA.AppliesToCommunity("udap://community-b").Returns(false);
        validatorA.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
        });

        var validatorB = Substitute.For<ICommunityTokenValidator>();
        validatorB.AppliesToCommunity("udap://community-a").Returns(false);
        validatorB.AppliesToCommunity("udap://community-b").Returns(true);
        validatorB.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string>
            {
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B,
                TefcaConstants.UdapAuthorizationExtensions.TEFCAIAS
            }
        });
        validatorB.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        // Client in community-b should need both hl7-b2b and tefca_ias
        var validator = CreateValidator(clientStore, [validatorA, validatorB]);
        var context = CreateContext(communityId: "2", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("tefca_ias", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_CommunityNameNotResolved_NoEnforcement()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>(null));

        var validator = CreateValidator(clientStore);
        // No extensions — passes because community name didn't resolve
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region Grant Type Specific Extensions (via Community Validator)

    [Fact]
    public async Task GrantTypeSpecific_ClientCredentials_RequiresB2B_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
        });
        communityValidator.GetValidationRules("authorization_code").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions(), grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_ClientCredentials_MissingB2B_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
        });

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_AuthorizationCode_RequiresB2BUser_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);

        var b2bUser = new HL7B2BUserAuthorizationExtension();
        b2bUser.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2bUser.UserPerson = JsonDocument.Parse("{}").RootElement;

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER] = b2bUser
        };
        var context = CreateContext(communityId: "1", extensions: extensions, grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_AuthorizationCode_MissingB2BUser_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER }
        });

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_AuthorizationCode_WrongExtension_Fails()
    {
        // Client sends hl7-b2b but authorization_code requires hl7-b2b-user
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER }
        });

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions(), grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_AuthorizationCode_NoExtensionRequired_Succeeds()
    {
        // Community validator requires hl7-b2b for client_credentials but NOT for authorization_code
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
        });
        communityValidator.GetValidationRules("authorization_code").Returns(new CommunityValidationRules
        {
            RequiredExtensions = null // no extension needed for auth code
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", grantType: "authorization_code"); // no extensions

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_Community_ClientCredentials_RequiresB2B()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "Organization/1.2.3",
            OrganizationName = "Test QHIN"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "10", extensions: extensions, grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_Community_AuthorizationCode_RequiresB2BUser()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);

        // Client sends hl7-b2b (wrong for authorization_code)
        var context = CreateContext(communityId: "10", extensions: CreateValidB2BExtensions(), grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_Community_NullGrantRules_NoEnforcement()
    {
        // Community validator applies but returns null rules for the grant type — no enforcement
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        // No enforcement — community validator returned null rules
        Assert.True(result.IsValid);
    }

    #endregion

    #region Purpose of Use Validation (via Community Validators)

    [Fact]
    public async Task CommunityValidator_AllowedPurposeOfUse_ValidCode_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT", "urn:oid:2.16.840.1.113883.5.8#ETREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_AllowedPurposeOfUse_DisallowedCode_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.5.8#ETREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        // CreateValidB2BExtensions uses TREAT, which is not in the allowed set
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("TREAT", result.ErrorDescription);
        Assert.Contains("disallowed", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_NullAllowList_AnyCodeAccepted()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = null
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_MaxPurposeOfUseCount_ExceedsLimit_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            MaxPurposeOfUseCount = 1
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#ETREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("maximum allowed is 1", result.ErrorDescription);
    }

    #endregion

    #region ErrorExtensions

    [Fact]
    public void ErrorExtensions_Failure_Factory_Carries_Extensions()
    {
        var errorExtensions = new Dictionary<string, object>
        {
            ["hl7-b2b"] = new
            {
                consent_required = new[] { "urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1" },
                consent_form = "https://tefca.example.com/consent/form.pdf"
            }
        };

        var result = AuthorizationExtensionValidationResult.Failure(
            "invalid_grant",
            "Consent policy required",
            errorExtensions);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Equal("Consent policy required", result.ErrorDescription);
        Assert.NotNull(result.ErrorExtensions);
        Assert.True(result.ErrorExtensions.ContainsKey("hl7-b2b"));
    }

    [Fact]
    public void ErrorExtensions_Standard_Failure_Has_Null_Extensions()
    {
        var result = AuthorizationExtensionValidationResult.Failure(
            "invalid_grant",
            "Missing required extension");

        Assert.False(result.IsValid);
        Assert.Null(result.ErrorExtensions);
    }

    [Fact]
    public void ErrorExtensions_Success_Has_Null_Extensions()
    {
        var result = AuthorizationExtensionValidationResult.Success();

        Assert.True(result.IsValid);
        Assert.Null(result.ErrorExtensions);
    }

    #endregion

    #region CommunityValidatorsAlwaysRun

    [Fact]
    public async Task CommunityValidators_RunEvenWhenNoExtensionsRequired_AuthorizationCode()
    {
        // Arrange: community validator returns null rules (no extensions required)
        // but ValidateAsync rejects — validator should still be invoked
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                "invalid_grant", "community validator rejected")));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "10", grantType: "authorization_code");

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert: community validator was invoked and its rejection is returned
        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("community validator rejected", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidators_RunEvenWhenNoExtensionsRequired_Success()
    {
        // Arrange: community validator returns success
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "10", grantType: "authorization_code");

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidators_NotInvokedForNonMatchingCommunity()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(false);

        var validator = CreateValidator(clientStore, [communityValidator]);
        var context = CreateContext(communityId: "10", grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
        await communityValidator.DidNotReceive().ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>());
    }

    #endregion

    #region Helpers

    private DefaultUdapAuthorizationExtensionValidator CreateValidator(
        IUdapClientRegistrationStore? clientStore = null,
        IEnumerable<ICommunityTokenValidator>? communityValidators = null)
    {
        clientStore ??= Substitute.For<IUdapClientRegistrationStore>();

        return new DefaultUdapAuthorizationExtensionValidator(
            clientStore,
            communityValidators ?? Enumerable.Empty<ICommunityTokenValidator>(),
            _logger);
    }

    /// <summary>
    /// Creates a community validator mock with a matching client store for community "udap://community-a" (ID "1").
    /// </summary>
    private static (IUdapClientRegistrationStore clientStore, ICommunityTokenValidator communityValidator) SetupCommunityValidator(
        HashSet<string>? requiredExtensions = null,
        HashSet<string>? allowedPurposeOfUse = null,
        int? maxPurposeOfUseCount = null,
        string communityName = "udap://community-a",
        string communityId = "1",
        string grantType = "client_credentials")
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName(communityId).Returns(Task.FromResult<string?>(communityName));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity(communityName).Returns(true);
        communityValidator.GetValidationRules(grantType).Returns(new CommunityValidationRules
        {
            RequiredExtensions = requiredExtensions,
            AllowedPurposeOfUse = allowedPurposeOfUse,
            MaxPurposeOfUseCount = maxPurposeOfUseCount
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        return (clientStore, communityValidator);
    }

    private static UdapAuthorizationExtensionValidationContext CreateContext(
        Dictionary<string, object>? extensions = null,
        string? communityId = null,
        string clientId = "test-client",
        string grantType = "client_credentials")
    {
        // Create a minimal valid JWT for the context
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(
            handler.CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
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

    private static Dictionary<string, object> CreateValidB2BExtensions()
    {
        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99",
            OrganizationName = "FhirLabs"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        return new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
    }

    #endregion
}
