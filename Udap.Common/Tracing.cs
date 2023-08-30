#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;

namespace Udap.Common;

public static class Tracing
{
    public static readonly string Validation = TraceNames.Validation;

    private static readonly Version AssemblyVersion = typeof(Tracing).Assembly.GetName().Version!;

    /// <summary>
    /// Store ActivitySource
    /// </summary>
    public static ActivitySource StoreActivitySource { get; } = new(
        TraceNames.Store,
        ServiceVersion);


    /// <summary>
    /// Detailed validation ActivitySource
    /// </summary>
    public static ActivitySource ValidationActivitySource { get; } = new(
        TraceNames.Validation,
        ServiceVersion);


    /// <summary>
    /// Service version
    /// </summary>
    public static string ServiceVersion => $"{AssemblyVersion.Major}.{AssemblyVersion.Minor}.{AssemblyVersion.Build}";


    public static class TraceNames
    {
        /// <summary>
        /// Service name for base traces
        /// </summary>
        public static string Basic => "Udap.Server";

        /// <summary>
        /// Service name for store traces
        /// </summary>
        public static string Store => Basic + ".Stores";


        /// <summary>
        /// Service name for detailed validation traces
        /// </summary>
        public static string Validation => Basic + ".Validation";
    }

    public static class Properties
    {
        public const string EndpointType = "endpoint_type";

        public const string ClientId = "client_id";
        public const string IdPBaseUrl = "idp_base_url";
        public const string GrantType = "grant_type";
        public const string Scope = "scope";
        public const string Resource = "resource";

        public const string Origin = "origin";
        public const string Scheme = "scheme";
        public const string Type = "type";
        public const string Id = "id";
        public const string ScopeNames = "scope_names";
        public const string ApiResourceNames = "api_resource_names";

        public const string Community = "Community_Name";
        public const string CommunityId = "CommunityId";
        public const string AnchorCertificate = "anchor_certificate";
        public const string RootCertificate = "root_certificate";
    }
}