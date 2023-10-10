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
namespace Microsoft.Extensions.DependencyInjection;


public class UdapServiceBuilder : IUdapServiceBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UdapServiceBuilder"/> class.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <exception cref="System.ArgumentNullException">services</exception>
    public UdapServiceBuilder(IServiceCollection services)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
    }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
