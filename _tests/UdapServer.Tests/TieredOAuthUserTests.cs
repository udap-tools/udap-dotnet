#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Duende.IdentityModel;
using Duende.IdentityServer;
using Udap.Server;

namespace UdapServer.Tests;

public class TieredOAuthUserTests
{
    [Fact]
    public void Constructor_ValidSubjectId_SetsProperty()
    {
        var user = new TieredOAuthUser("user-123");

        Assert.Equal("user-123", user.SubjectId);
    }

    [Fact]
    public void Constructor_EmptySubjectId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new TieredOAuthUser(""));
    }

    [Fact]
    public void Constructor_NullSubjectId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new TieredOAuthUser(null!));
    }

    [Fact]
    public void Constructor_DefaultCollections_AreEmpty()
    {
        var user = new TieredOAuthUser("sub-1");

        Assert.Empty(user.AuthenticationMethods);
        Assert.Empty(user.AdditionalClaims);
        Assert.Null(user.DisplayName);
        Assert.Null(user.IdentityProvider);
        Assert.Null(user.Tenant);
        Assert.Null(user.AuthenticationTime);
    }

    [Fact]
    public void CreatePrincipal_MinimalUser_HasSubjectClaim()
    {
        var user = new TieredOAuthUser("sub-1");

        var principal = user.CreatePrincipal();

        Assert.NotNull(principal.Identity);
        Assert.True(principal.Identity.IsAuthenticated);
        Assert.Equal("sub-1", principal.FindFirst(JwtClaimTypes.Subject)?.Value);
    }

    [Fact]
    public void CreatePrincipal_WithDisplayName_IncludesNameClaim()
    {
        var user = new TieredOAuthUser("sub-1") { DisplayName = "Joe Shook" };

        var principal = user.CreatePrincipal();

        Assert.Equal("Joe Shook", principal.FindFirst(JwtClaimTypes.Name)?.Value);
    }

    [Fact]
    public void CreatePrincipal_WithoutDisplayName_NoNameClaim()
    {
        var user = new TieredOAuthUser("sub-1");

        var principal = user.CreatePrincipal();

        Assert.Null(principal.FindFirst(JwtClaimTypes.Name));
    }

    [Fact]
    public void CreatePrincipal_WithIdentityProvider_IncludesIdpClaim()
    {
        var user = new TieredOAuthUser("sub-1") { IdentityProvider = "https://idp.example.com" };

        var principal = user.CreatePrincipal();

        Assert.Equal("https://idp.example.com", principal.FindFirst(JwtClaimTypes.IdentityProvider)?.Value);
    }

    [Fact]
    public void CreatePrincipal_WithoutIdentityProvider_NoIdpClaim()
    {
        var user = new TieredOAuthUser("sub-1");

        var principal = user.CreatePrincipal();

        Assert.Null(principal.FindFirst(JwtClaimTypes.IdentityProvider));
    }

    [Fact]
    public void CreatePrincipal_WithTenant_IncludesTenantClaim()
    {
        var user = new TieredOAuthUser("sub-1") { Tenant = "tenant-abc" };

        var principal = user.CreatePrincipal();

        Assert.Equal("tenant-abc", principal.FindFirst(IdentityServerConstants.ClaimTypes.Tenant)?.Value);
    }

    [Fact]
    public void CreatePrincipal_WithoutTenant_NoTenantClaim()
    {
        var user = new TieredOAuthUser("sub-1");

        var principal = user.CreatePrincipal();

        Assert.Null(principal.FindFirst(IdentityServerConstants.ClaimTypes.Tenant));
    }

    [Fact]
    public void CreatePrincipal_WithAuthenticationTime_IncludesAuthTimeClaim()
    {
        var authTime = new DateTime(2026, 5, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = new TieredOAuthUser("sub-1") { AuthenticationTime = authTime };

        var principal = user.CreatePrincipal();

        var authTimeClaim = principal.FindFirst(JwtClaimTypes.AuthenticationTime);
        Assert.NotNull(authTimeClaim);
        var expectedEpoch = new DateTimeOffset(authTime).ToUnixTimeSeconds().ToString();
        Assert.Equal(expectedEpoch, authTimeClaim.Value);
    }

    [Fact]
    public void CreatePrincipal_WithoutAuthenticationTime_NoAuthTimeClaim()
    {
        var user = new TieredOAuthUser("sub-1");

        var principal = user.CreatePrincipal();

        Assert.Null(principal.FindFirst(JwtClaimTypes.AuthenticationTime));
    }

    [Fact]
    public void CreatePrincipal_WithAuthenticationMethods_IncludesAmrClaims()
    {
        var user = new TieredOAuthUser("sub-1");
        user.AuthenticationMethods.Add("pwd");
        user.AuthenticationMethods.Add("mfa");

        var principal = user.CreatePrincipal();

        var amrClaims = principal.FindAll(JwtClaimTypes.AuthenticationMethod).Select(c => c.Value).ToList();
        Assert.Contains("pwd", amrClaims);
        Assert.Contains("mfa", amrClaims);
        Assert.Equal(2, amrClaims.Count);
    }

    [Fact]
    public void CreatePrincipal_WithAdditionalClaims_IncludesThem()
    {
        var user = new TieredOAuthUser("sub-1");
        user.AdditionalClaims.Add(new Claim("custom_claim", "custom_value"));
        user.AdditionalClaims.Add(new Claim(JwtClaimTypes.Email, "joe@example.com"));

        var principal = user.CreatePrincipal();

        Assert.Equal("custom_value", principal.FindFirst("custom_claim")?.Value);
        Assert.Equal("joe@example.com", principal.FindFirst(JwtClaimTypes.Email)?.Value);
    }

    [Fact]
    public void CreatePrincipal_AllPropertiesSet_IncludesAllClaims()
    {
        var authTime = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var user = new TieredOAuthUser("sub-full")
        {
            DisplayName = "Full User",
            IdentityProvider = "https://idp.test",
            Tenant = "tenant-1",
            AuthenticationTime = authTime
        };
        user.AuthenticationMethods.Add("pwd");
        user.AdditionalClaims.Add(new Claim("org", "Acme"));

        var principal = user.CreatePrincipal();

        Assert.Equal("sub-full", principal.FindFirst(JwtClaimTypes.Subject)?.Value);
        Assert.Equal("Full User", principal.FindFirst(JwtClaimTypes.Name)?.Value);
        Assert.Equal("https://idp.test", principal.FindFirst(JwtClaimTypes.IdentityProvider)?.Value);
        Assert.Equal("tenant-1", principal.FindFirst(IdentityServerConstants.ClaimTypes.Tenant)?.Value);
        Assert.NotNull(principal.FindFirst(JwtClaimTypes.AuthenticationTime));
        Assert.Equal("pwd", principal.FindFirst(JwtClaimTypes.AuthenticationMethod)?.Value);
        Assert.Equal("Acme", principal.FindFirst("org")?.Value);
    }

    [Fact]
    public void CreatePrincipal_IdentityAuthenticationType_IsIdentityServer()
    {
        var user = new TieredOAuthUser("sub-1");

        var principal = user.CreatePrincipal();

        Assert.Equal(Constants.IdentityServerAuthenticationType, principal.Identity?.AuthenticationType);
    }

    [Fact]
    public void CreatePrincipal_DuplicateClaims_AreDeduped()
    {
        var user = new TieredOAuthUser("sub-1");
        user.AdditionalClaims.Add(new Claim(JwtClaimTypes.Subject, "sub-1"));

        var principal = user.CreatePrincipal();

        var subClaims = principal.FindAll(JwtClaimTypes.Subject).ToList();
        Assert.Single(subClaims);
    }
}
