// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using IdentityModel;
using System.Security.Claims;
using System.Text.Json;
using Duende.IdentityServer;
using Duende.IdentityServer.Test;

namespace Udap.Identity.Provider;

public class TestUsers
{
    public static List<TestUser> Users
    {
        get
        {
            var address = new
            {
                street_address = "One Hacker Way",
                locality = "Heidelberg",
                postal_code = 69118,
                country = "Germany"
            };
                
            return new List<TestUser>
            {
                new TestUser
                {
                    SubjectId = "1",
                    Username = "alicenewman@example.com",
                    Password = "alice",
                    Claims =
                    {
                        new Claim(JwtClaimTypes.Name, "Alice Newman"),
                        new Claim(JwtClaimTypes.Locale, "en_US`"),
                        new Claim(JwtClaimTypes.GivenName, "Alice"),
                        new Claim(JwtClaimTypes.MiddleName, "Jones"),
                        new Claim(JwtClaimTypes.FamilyName, "Newman"),
                        new Claim(JwtClaimTypes.Email, "alicenewman@example.com"),
                        new Claim(JwtClaimTypes.PreferredUserName, "alicenewman@example.com"),
                        new Claim(JwtClaimTypes.ZoneInfo, "America/Los_Angeles"),
                        new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        // new Claim(JwtClaimTypes.WebSite, "http://alice.com"),
                        new Claim("hl7_identifier", "123e4567-e89b-12d3-a456-426614174000a"),
                        // new Claim(JwtClaimTypes.Address, JsonSerializer.Serialize(address), IdentityServerConstants.ClaimValueTypes.Json)
                        new Claim("fhirUser", "https://stage.healthtogo.me:8181/fhir/r4/stage/Patient/1001")
                    }
                },

                new TestUser
                {
                    SubjectId = "2",
                    Username = "bob",
                    Password = "bob",
                    Claims =
                    {
                        new Claim(JwtClaimTypes.Name, "Bob Smith"),
                        new Claim(JwtClaimTypes.GivenName, "Bob"),
                        new Claim(JwtClaimTypes.FamilyName, "Smith"),
                        new Claim(JwtClaimTypes.Email, "BobSmith@email.com"),
                        new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        new Claim(JwtClaimTypes.WebSite, "http://bob.com"),
                        new Claim(JwtClaimTypes.Address, JsonSerializer.Serialize(address), IdentityServerConstants.ClaimValueTypes.Json)
                    }
                }
            };
        }
    }
}