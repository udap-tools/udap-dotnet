#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
using Microsoft.Extensions.DependencyInjection;

public interface IUdapServiceBuilder
{
    /// <summary>
    /// Gets the services.
    /// </summary>
    /// <value>
    /// The services.
    /// </value>
    IServiceCollection Services { get; }
}