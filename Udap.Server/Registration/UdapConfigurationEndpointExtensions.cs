#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Udap.Server.Registration;

public static class UdapConfigurationEndpointExtensions
{
    //TODO: this was not used.  Make sure it is used or drop it.
    public static IEndpointConventionBuilder MapUdapDynamicClientRegistration(this IEndpointRouteBuilder endpoints, string path)
    {
        using var scope = endpoints.ServiceProvider.CreateScope();
        var endpoint = scope.ServiceProvider.GetRequiredService<UdapDynamicClientRegistrationEndpoint>();


        //TODO: What happens during an exception?
        return endpoints.MapPost(path, endpoint.Process);
    }
}