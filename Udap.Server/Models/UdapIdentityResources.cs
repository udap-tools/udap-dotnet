#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;
using Udap.Model;

namespace Udap.Server.Models;

public static class UdapIdentityResources
{
    /// <summary>
    /// Models the standard openid scope
    /// </summary>
    /// <seealso cref="IdentityServer.Models.IdentityResource" />
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
            UserClaims.Add("fhir_resource");
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
