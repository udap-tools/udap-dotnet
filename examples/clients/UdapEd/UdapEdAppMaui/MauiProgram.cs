#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Blazored.LocalStorage;
using Microsoft.Extensions.Logging;
using MudBlazor.Services;
using UdapEd.Shared.Services;
using UdapEdAppMaui.Services;

namespace UdapEdAppMaui;
public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
            });

        builder.Services.AddMauiBlazorWebView();

        builder.Services.AddScoped(sp => new HttpClient
        {
            BaseAddress = new Uri("http://localhost")
        });

        builder.Services.AddMudServices();
        builder.Services.AddBlazoredLocalStorage();

        builder.Services.AddSingleton<UdapClientState>(); //Singleton in Blazor wasm and Scoped in Blazor Server
        builder.Services.AddScoped<IRegisterService, RegisterService>();
        builder.Services.AddScoped<IDiscoveryService, DiscoveryService>();
        builder.Services.AddScoped<IAccessService, AccessService>();
        builder.Services.AddScoped<IFhirService, FhirService>();


#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
		builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}
