#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using MudBlazor.Services;
using UdapClient.Client;
using UdapClient.Client.Services;
using UdapClient.Client.Shared;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");


builder.Services.AddScoped(sp => new HttpClient
{
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress)
});

builder.Services.AddMudServices();
builder.Services.AddBlazoredLocalStorage();

builder.Services.AddSingleton<UdapClientState>(); //Singleton in Blazor wasm and Scoped in Blazor Server
builder.Services.AddScoped<RegisterService>();
builder.Services.AddScoped<DiscoveryService>();
builder.Services.AddScoped<AccessService>();

await builder.Build().RunAsync();
