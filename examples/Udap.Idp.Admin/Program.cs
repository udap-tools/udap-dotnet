/*
 Copyright (c) Joseph Shook. All rights reserved.
 Authors:
    Joseph Shook   Joseph.Shook@Surescripts.com

 See LICENSE in the project root for license information.
*/

using Serilog;
using Udap.Idp.Admin;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
        .Enrich.FromLogContext()
        .ReadFrom.Configuration(ctx.Configuration));

    if (builder.PrepDataBase(args, Log.Logger))
    {
        return 0;
    }

    var app = builder
        .ConfigureServices()
        .ConfigurePipeline();

    app.Run();

    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception");

    return 1;
}
finally
{
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}


//
// Accessible to unit tests
//
namespace Udap.Idp.Admin
{
    public partial class Program { }
}
