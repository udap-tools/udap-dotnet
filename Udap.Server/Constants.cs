#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

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
            public const string DiscoveryConfiguration = ".well-known/udap";
            public const string Register = ConnectPathPrefix + "/register";
        }
    }
}
