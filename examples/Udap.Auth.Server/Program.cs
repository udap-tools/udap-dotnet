#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using Udap.Auth.Server;

Activity.DefaultIdFormat = ActivityIdFormat.W3C;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

try
{
    var builder = WebApplication.CreateBuilder(args);


    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(
            outputTemplate:
            "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}",
            theme: AnsiConsoleTheme.Code)
        .MinimumLevel.Verbose()
        .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
        .MinimumLevel.Override("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", LogEventLevel.Information)
        .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
        .MinimumLevel.Override("System", LogEventLevel.Warning)
        .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
        .Enrich.FromLogContext(), 
        true);

    // builder.Host.UseSerilog((ctx, lc) => lc
    //     .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
    //     .Enrich.FromLogContext()
    //     .ReadFrom.Configuration(ctx.Configuration));

    // Mount Cloud Secrets
    builder.Configuration.AddJsonFile("/secret/udap_auth_appsettings", true, false);

    var app = builder
        .ConfigureServices(args)
        .ConfigurePipeline(args);

    //
    // Created to route traffic through AEGIS Touchstone via a Nginx reverse proxy in my cloud environment.
    // Touchstone is also a proxy used to surveil traffic for testing and certification.  
    //
    if (Environment.GetEnvironmentVariable("proxy-hosts") != null)
    {
        var hostMaps = Environment.GetEnvironmentVariable("proxy-hosts")?.Split(";");
        foreach (var hostMap in hostMaps!)
        {
            Log.Information($"Adding host map: {hostMap}");
            File.AppendAllText("/etc/hosts", hostMap + Environment.NewLine);
        }
    }
    
    app.Run();
}
catch (Exception ex)
{
    if (ex.GetType().Name != "StopTheHostException")
    {
        Log.Fatal(ex, "Unhandled exception");
    }
}
finally
{
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}

//
// Accessible to unit tests
//
namespace Udap.Auth.Server
{
    public partial class Program { }
}