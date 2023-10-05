#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;
using Udap.Model;

namespace Udap.Server.Models;

public static class UdapIdentityResources
{
    /// <summary>
    /// Models the standard openid scope
    /// </summary>
    /// <seealso cref="IdentityResource" />
    public class FhirUser : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FhirUser"/> class.
        /// </summary>
        public FhirUser()
        {
            Name = UdapConstants.StandardScopes.FhirUser;
            DisplayName = "FHIR resource representation of the current user.";
            Required = false;
            UserClaims.Add(UdapConstants.JwtClaimTypes.Hl7Identifier);
        }
    }

    /// <summary>
    /// Models the standard openid scope
    /// </summary>
    /// <seealso cref="IdentityResource" />
    public class Profile : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Profile"/> class.
        /// </summary>
        public Profile()
        {
            var profile = new IdentityResources.Profile();
            Name = profile.Name;
            DisplayName = profile.DisplayName;
            Required = profile.Required;
            UserClaims = profile.UserClaims;
            //
            // Ensure HL7Identifier is included in the profile scope when the profile scope is requested
            // http://build.fhir.org/ig/HL7/fhir-identity-matching-ig/digital-identity.html 
            // http://hl7.org/fhir/smart-app-launch/1.0.0/scopes-and-launch-context/index.html
            //
            UserClaims.Add(UdapConstants.JwtClaimTypes.Hl7Identifier);
        }
    }

    public class Udap : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Udap"/> class.
        /// </summary>
        public Udap()
        {
            Name = UdapConstants.StandardScopes.Udap;
            DisplayName = "UDAP resource to signal to the receiver that UDAP Tiered OAuth for User Authentication is being requested";
            Required = false;
        }
    }
}
