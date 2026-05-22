#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Storage;

public static class UdapServerConstants
{
    public static class SecretTypes
    {
        public const string UDAP_SAN_URI_ISS_NAME = "UDAP_SAN_URI_ISS_NAME";
        public const string UDAP_COMMUNITY = "UDAP_COMMUNITY";
        public const string UDAP_X509_CERTIFICATE = "X509CertificateBase64";
    }

    public static class ClientPropertyConstants
    {
        public const string Organization = "org";
        public const string DataHolder = "data_holder";
        public const string DefaultOrgMap = "empty";
    }

    public static class HttpContextItems
    {
        public const string UdapErrorDescription = "udap:error_description";
        public const string UdapErrorExtensions = "udap:error_extensions";
    }
}
