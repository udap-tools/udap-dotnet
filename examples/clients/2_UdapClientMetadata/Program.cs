#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.CommandLine;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Udap.Client;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Util.Extensions;

class Program
{
    static int Main(string[] args)
    {
        Option<string> baseUrlOption = new("--baseUrl")
        {
            Description = "The base URL of the FHIR server",
            Required = true
        };

        Option<string> trustAnchorOption = new("--trustAnchor")
        {
            Description = "Path to trust anchor certificate"
        };

        Option<string> communityOption = new("--community")
        {
            Description = "UDAP community URI"
        };

        RootCommand rootCommand = new(@"$ dotnet run --baseUrl 'https://fhirlabs.net/fhir/r4' --community 'udap://fhirlabs.net/'

Other --community options to try against the https://fhirlabs.net/fhir/r4 baseUrl

--community 'udap://expired.fhirlabs.net/'
--community 'udap://expired.fhirlabs.net/'
--community 'udap://revoked.fhirlabs.net/'
--community 'udap://untrusted.fhirlabs.net/'
--community 'udap://Iss.Miss.Match.To.SubjAltName/'
--community 'udap://Iss.Miss.Match.To.BaseUrl/'
--community 'udap://ECDSA/'

")
        {
            baseUrlOption,
            trustAnchorOption,
            communityOption
        };

        rootCommand.SetAction(parseResult =>
        {
            var baseUrl = parseResult.GetValue(baseUrlOption)!;
            var community = parseResult.GetValue(communityOption);

            using var host = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    services.Configure<UdapFileCertStoreManifest>(context.Configuration.GetSection("UdapFileCertStoreManifest"));
                    services.AddSingleton<ITrustAnchorStore, TrustAnchorFileStore>();
                    services.AddScoped<TrustChainValidator>();
                    services.AddSingleton<UdapClientDiscoveryValidator>();
                    services.AddHttpClient<IUdapClient, UdapClient>();
                })
                .Build();

            Run(baseUrl, community, host);
        });

        return rootCommand.Parse(args).Invoke();
    }

    private static void Run(string baseUrl, string? community, IHost host)
    {
        var serviceProvider = host.Services;
        var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
        var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger(typeof(Program));

        udapClient.Problem += element => logger.LogWarning(element.Problems.Summarize(TrustChainValidator.DefaultProblemFlags));
        udapClient.Untrusted += certificate2 => logger.LogWarning("Untrusted: " + certificate2.Subject);
        udapClient.TokenError += message => logger.LogWarning("TokenError: " + message);

        logger.LogInformation($"Requesting {baseUrl}");
        var response = udapClient.ValidateResource(baseUrl, community).GetAwaiter().GetResult();

        if (response.IsError)
        {
            logger.LogError(response.Error);
        }
        else
        {
            logger.LogInformation(JsonSerializer.Serialize(udapClient.UdapServerMetadata, new JsonSerializerOptions{WriteIndented = true}));
        }
    }
}