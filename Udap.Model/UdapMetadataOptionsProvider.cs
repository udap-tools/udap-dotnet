using System;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace Udap.Model;
public interface IUdapMetadataOptionsProvider
{
    UdapMetadataOptions Value { get; }
}

public class UdapMetadataOptionsProvider : IUdapMetadataOptionsProvider
{
    public UdapMetadataOptions Value { get; }

    public UdapMetadataOptionsProvider(IConfiguration configuration)
    {
        var file = configuration["UdapMetadataOptionsFile"] ?? "udap.metadata.options.json";
        try
        {
            var json = File.ReadAllText(file);
            Value = JsonSerializer.Deserialize<UdapMetadataOptions>(
                json,
                new JsonSerializerOptions()
                {
                    ReadCommentHandling = JsonCommentHandling.Skip
                })!;
        }
        catch (Exception)
        {
            throw new InvalidOperationException("UDAP metadata configuration could not be loaded. Please contact the administrator.");
        }
    }
}
