using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;

public class HL7B2BUserAuthorizationExtensionConverter : JsonConverter<HL7B2BUserAuthorizationExtension>
{
    private readonly bool _indent;

    public HL7B2BUserAuthorizationExtensionConverter(bool indent = false)
    {
        _indent = indent;
    }

    public override HL7B2BUserAuthorizationExtension Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(ref reader, options);
        var extension = new HL7B2BUserAuthorizationExtension();
        foreach (var kvp in dictionary)
        {
            if (kvp.Value is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.Array)
            {
                var list = JsonSerializer.Deserialize<List<string>>(jsonElement.GetRawText(), options);
                var properties = typeof(HL7B2BUserAuthorizationExtension).GetProperties(BindingFlags.Public | BindingFlags.Instance);

                bool propertySet = false;

                foreach (var property in properties)
                {
                    var jsonPropertyNameAttribute = property.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false)
                        .FirstOrDefault() as JsonPropertyNameAttribute;

                    if (jsonPropertyNameAttribute != null && jsonPropertyNameAttribute.Name == kvp.Key)
                    {
                        if (property.CanWrite)
                        {
                            property.SetValue(extension, list);
                            propertySet = true;
                            break;
                        }
                    }
                }
            }            
            else
            {
                extension[kvp.Key] = kvp.Value;
            }
        }
        return extension;
    }

    public override void Write(Utf8JsonWriter writer, HL7B2BUserAuthorizationExtension value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        var properties = value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        foreach (var property in properties)
        {
            if (property.CanRead && property.GetValue(value) is object propertyValue)
            {
                var jsonPropertyName = property.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false)
                    .FirstOrDefault() as JsonPropertyNameAttribute;
                var propertyName = jsonPropertyName?.Name ?? property.Name;

                if (property.Name == "UserPerson")
                {
                    var parser = new FhirJsonParser();
                    var personResource = parser.Parse<Person>(propertyValue.ToString());
                    var serializer = new FhirJsonSerializer(new SerializerSettings() { Pretty = _indent });
                    var serializedPerson = serializer.SerializeToString(personResource);

                    writer.WritePropertyName(propertyName);
                    writer.WriteRawValue(serializedPerson);
                }
                else
                {
                    writer.WritePropertyName(propertyName);
                    JsonSerializer.Serialize(writer, propertyValue, propertyValue.GetType(), options);
                }
            }
        }

        writer.WriteEndObject();
    }
}