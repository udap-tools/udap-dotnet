﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.CommandLine;
using System.CommandLine.Hosting;
using System.CommandLine.NamingConventionBinder;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Udap.Client.Client;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Util.Extensions;

class Program
{
    static Task Main(string[] args) => BuildCommandLine()
        .UseHost(_ => Host.CreateDefaultBuilder(),
            host =>
            {
                host.ConfigureServices(services =>
                {
                    services.AddScoped<TrustChainValidator>();
                    services.AddSingleton<UdapClientDiscoveryValidator>();
                    services.AddHttpClient<IUdapClient, UdapClient>();
                    
                });
            })
        .InvokeAsync(args);

    private static CliConfiguration BuildCommandLine()
    {
        var root = new CliRootCommand(@"$ dotnet run --baseUrl 'https://fhirlabs.net/fhir/r4' --trustAnchor './myTrustAnchor.cer' --community 'udap://fhirlabs.net/' 

Other --community options to try against the https://fhirlabs.net/fhir/r4 baseUrl

--community 'udap://expired.fhirlabs.net/'
--community 'udap://expired.fhirlabs.net/'
--community 'udap://revoked.fhirlabs.net/'
--community 'udap://untrusted.fhirlabs.net/'
--community 'udap://Iss.Miss.Match.To.SubjAltName/'
--community 'udap://Iss.Miss.Match.To.BaseUrl/'
--community 'udap://ECDSA/'

"){
            
            new CliOption<string>("--baseUrl"){
                Required = true
            },
            new CliOption<string>("--trustAnchor")
            {
                Required = false
            },
            new CliOption<string>("--community")
            {
                Required = false
            }
        };
        root.Action = CommandHandler.Create<ClientOptions, IHost>(Run);
        return new CliConfiguration(root);
    }

    private static void Run(ClientOptions options, IHost host)
    {
        var serviceProvider = host.Services;
        var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
        var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger(typeof(Program));


        TrustAnchorMemoryStore? trustAnchorStore = null;
        if (!string.IsNullOrEmpty(options.TrustAnchor))
        {
            var anchorCert = new X509Certificate2(options.TrustAnchor);
            trustAnchorStore = new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
                    new Anchor(anchorCert)
                }
            };
        }

        string? community = options.Community;

        udapClient.Problem += element => logger.LogWarning(element.ChainElementStatus.Summarize(TrustChainValidator.DefaultProblemFlags));
        udapClient.Untrusted += certificate2 => logger.LogWarning("Untrusted: " + certificate2.Subject);
        udapClient.TokenError += message => logger.LogWarning("TokenError: " + message);

        
        logger.LogInformation($"Requesting {options.BaseUrl}");
        var response = udapClient.ValidateResource(options.BaseUrl, trustAnchorStore, community).GetAwaiter().GetResult();

        if (response.IsError)
        {
            logger.LogError(response.HttpErrorReason);
        }
        else
        {
            logger.LogInformation(JsonSerializer.Serialize(udapClient.UdapServerMetaData, new JsonSerializerOptions{WriteIndented = true})); 
        }
    }
}

public class ClientOptions
{
    public ClientOptions(string baseUrl, string? trustAnchor, string? community)
    {
        BaseUrl = baseUrl;
        TrustAnchor = trustAnchor;
        Community = community;
    }

    public string BaseUrl { get; }

    public string? TrustAnchor { get; }

    public string?Community { get; }
}