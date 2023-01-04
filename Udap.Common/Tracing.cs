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
    private static readonly Version AssemblyVersion = typeof(Tracing).Assembly.GetName().Version;

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
        /// Service name for detailed validation traces
        /// </summary>
        public static string Validation => Basic + ".Validation";
    }
}