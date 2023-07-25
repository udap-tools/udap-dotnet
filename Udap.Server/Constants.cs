#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// Many of these constants originate from Duende.IdentityServer
// Most are to facilitate Unit/Integration tests because they are internal to Duende.IdentityServer

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

namespace Udap.Server
{
    internal static class Constants
    {
        public static class EndpointNames
        {
            public const string Discovery = "Discovery";
        }

        public static class ProtocolRoutePaths
        {
            public const string ConnectPathPrefix = "connect";

            public const string Authorize = ConnectPathPrefix + "/authorize";
            public const string DiscoveryConfiguration = ".well-known/udap";
            public const string Register = ConnectPathPrefix + "/register";
            public const string Token = ConnectPathPrefix + "/token";
        }

        public static class TieredOAuthConstants
        {
            public const string ClientRandomState = "client_random_state";
            public const string ResourceHolderRandomState = "resource_holder_random_state";
        }

        public static class EndpointAuthenticationMethods
        {
            public const string UdapPkiJwt = "udap_pki_jwt";
        }

        public static class TokenErrors
        {
            public const string MissingSecurityToken = "Missing security token";
        }

        public static class UIConstants
        {
            // the limit after which old messages are purged
            public const int CookieMessageThreshold = 2;

            public static class DefaultRoutePathParams
            {
                public const string Error = "errorId";
                public const string Login = "returnUrl";
                public const string Consent = "returnUrl";
                public const string Logout = "logoutId";
                public const string EndSessionCallback = "endSessionId";
                public const string Custom = "returnUrl";
                public const string UserCode = "userCode";
            }

            public static class DefaultRoutePaths
            {
                public const string Login = "/account/login";
                public const string Logout = "/account/logout";
                public const string Consent = "/consent";
                public const string Error = "/home/error";
                public const string DeviceVerification = "/device";
            }
        }

        public const string IdentityServerName = "Udap.Authorizaton.Server";
        public const string IdentityServerAuthenticationType = IdentityServerName;
    }
}
