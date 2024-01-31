#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

//
// The following test and pipeline technique are from the original Duende source code tests.
// I will be adapting these to test UDAP specific features where some of the tests are identical
// as I do want the resulting UDAP features to live in harmony with the existing Identity Server.
//

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using FluentAssertions;
using UdapServer.Tests.Common;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class ResponseTypeResponseModeTests
{
    private IdentityServerPipeline _mockPipeline = new IdentityServerPipeline();

    public ResponseTypeResponseModeTests()
    {
        _mockPipeline.Initialize();
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        _mockPipeline.Clients.Add(new Client
        {
            Enabled = true,
            ClientId = "code_client",
            ClientSecrets = new List<Secret>
            {
                new Secret("secret".Sha512())
            },

            AllowedGrantTypes = GrantTypes.Code,
            AllowedScopes = { "openid" },

            RequireConsent = false,
            RequirePkce = false,
            RedirectUris = new List<string>
            {
                "https://code_client/callback"
            }
        });

        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());

        _mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new Claim[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });
    }

    //
    // The following comment below the **** is from the original source code.
    // I will be creating a mockPipeline for UDAP in another test class.
    // It will return 400-599 errors or redirect with the
    // error and error_description in the query params.
    //


    // ****
    // this might not be in sync with the actual conformance tests
    // since we dead-end on the error page due to changes 
    // to follow the RFC to address open redirect in original OAuth RFC
    [Fact]
    public async Task Request_missing_response_type_rejected()
    {
        await _mockPipeline.LoginAsync("bob");

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: "code_client",
            responseType: null, // missing
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;
        var response = await _mockPipeline.BrowserClient.GetAsync(url);

        _mockPipeline.ErrorMessage.Error.Should().Be("invalid_request");
    }
}
