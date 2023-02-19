using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace UdapEd.Server.Extensions;

public static class OpenTelemetryExtensions
{
    public static WebApplicationBuilder AddOpenTelemetry(this WebApplicationBuilder builder)
    {
        var resourceBuilder = ResourceBuilder.CreateDefault().AddService(builder.Environment.ApplicationName);

        builder.Services.AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics.SetResourceBuilder(resourceBuilder)
                    .AddAspNetCoreInstrumentation()
                    .AddRuntimeInstrumentation()
                    .AddHttpClientInstrumentation()
                    // .AddEventCountersInstrumentation(c =>
                    // {
                    //     // https://learn.microsoft.com/en-us/dotnet/core/diagnostics/available-counters
                    //     c.AddEventSources(
                    //         "Microsoft.AspNetCore.Hosting",
                    //         "Microsoft-AspNetCore-Server-Kestrel",
                    //         "System.Net.Http",
                    //         "System.Net.Sockets",
                    //         "System.Net.NameResolution",
                    //         "System.Net.Security");
                    // })
                    .AddOtlpExporter(otlpOptions =>
                    {
                        otlpOptions.Endpoint = new Uri("http://localhost:4317");
                    });
                ;
            })
            .WithTracing(builder =>
            {
                builder.SetResourceBuilder(resourceBuilder)
                    .AddHttpClientInstrumentation()
                    .AddAspNetCoreInstrumentation()
                    // .AddConsoleExporter();
                    .AddOtlpExporter(otlpOptions =>
                    {
                        otlpOptions.Endpoint = new Uri("http://localhost:4317");
                    });
            });

        return builder;
    }
}
