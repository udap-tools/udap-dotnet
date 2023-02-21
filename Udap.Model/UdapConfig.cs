#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;

namespace Udap.Model
{
    /// <summary>
    /// Configurable data typically loaded from AppSettings.
    /// </summary>
    public class UdapConfig
    {
        public List<UdapMetadataConfig> UdapMetadataConfigs { get; set; } = new();
    }

    public class UdapMetadataConfig
    {

        /// <summary>
        /// See <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#multiple-trust-communities">Multiple Trust Communities</a>
        /// </summary>
        public string Community { get; set; } = string.Empty;


        /// <summary>
        /// See <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#signed-metadata-elements">Signed metadata elements</a>
        /// Signed Metadata JWT claims
        /// </summary>
        public SignedMetadataConfig SignedMetadataConfig { get; set; } = new();
    }


    public class SignedMetadataConfig
    {
        private TimeSpan _expirationTimeSpan = new TimeSpan(0, 5, 0);

        public string Issuer { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;

        /// <summary>
        /// The expiration timespan SHALL be no more than 5 minutes after the value of
        /// issued (iat) time. 
        /// </summary>
        /// <remarks>Defaults to 5 minutes.  While in development mode the limit is not enforced.</remarks>
        public TimeSpan ExpirationTimeSpan
        {
            get => _expirationTimeSpan;
            set
            {
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") != "Development" &&
                    value > TimeSpan.FromMinutes(5))
                {
                    throw new ArgumentException(
                        $"{nameof(ExpirationTimeSpan)} SHALL be no more than 5 minutes after the value of the iat claim");
                }

                _expirationTimeSpan = value;
            }
        }

        public string AuthorizationEndpoint { get; set; } = string.Empty;

        public string TokenEndpoint { get; set; } = string.Empty;

        public string RegistrationEndpoint { get; set; } = string.Empty;


    }
}
