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
using Microsoft.Extensions.Options;
using Microsoft.Maui.LifecycleEvents;
using MudBlazor.Services;
using Serilog;
using Serilog.Events;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using UdapEd.Shared.Services;
using UdapEdAppMaui.Services;

#if WINDOWS
using WinUIEx;
#endif

namespace UdapEdAppMaui;
public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        var flushInterval = new TimeSpan(0, 0, 1);
        var file = Path.Combine(FileSystem.AppDataDirectory, "UdapEdAppMaui.log");

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .MinimumLevel.Override("Microsoft.AspNetCore.Components.RenderTree.Renderer", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Components.WebView", LogEventLevel.Verbose)
            .Enrich.FromLogContext()
            // .WriteTo.Console(
            //     outputTemplate:
            //     "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}",
            //     theme: AnsiConsoleTheme.Code)
#if ANDROID
            .WriteTo.AndroidLog()
#endif
            .WriteTo.File(file, 
                flushToDiskInterval: flushInterval,
                encoding: System.Text.Encoding.UTF8, 
                rollingInterval: RollingInterval.Day, 
                retainedFileCountLimit: 22,
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        builder.Logging.AddSerilog(dispose: true);

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
        builder.Services.AddScoped<IInfrastructure, Infrastructure>();


        builder.Services.AddScoped<TrustChainValidator>();
        builder.Services.AddScoped<UdapClientDiscoveryValidator>();
        builder.Services.AddHttpClient<IUdapClient, UdapClient>()
            .AddHttpMessageHandler(sp => new HeaderAugmentationHandler(sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>()));

#if WINDOWS
        builder.Services.AddSingleton<IExternalWebAuthenticator, WebAuthenticatorForWindows>();
#else
        builder.Services.AddSingleton<IExternalWebAuthenticator, WebAuthenticatorForDevice>();
#endif

#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
		builder.Logging.AddDebug();
#endif

#if WINDOWS
            builder.ConfigureLifecycleEvents(events =>
            {
                events.AddWindows(wndLifeCycleBuilder =>
                {
                    wndLifeCycleBuilder.OnWindowCreated(window =>
                    {
                        window.CenterOnScreen(1024,768); //Set size and center on screen using WinUIEx extension method

                        var manager = WinUIEx.WindowManager.Get(window);
                        manager.PersistenceId = "MainWindowPersistanceId"; // Remember window position and size across runs
                        manager.MinWidth = 640;
                        manager.MinHeight = 480;
                    });
                });
            });
#endif


        return builder.Build();
    }
}
