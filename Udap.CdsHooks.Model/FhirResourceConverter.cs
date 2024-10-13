#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;

namespace Udap.CdsHooks.Model;
public class FhirResourceConverter : JsonConverter<Dictionary<string, Resource>>
{
    private readonly FhirJsonParser _fhirJsonParser = new FhirJsonParser();

    public override Dictionary<string, Resource> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var prefetch = new Dictionary<string, Resource>();

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException();
        }

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return prefetch;
            }

            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException();
            }

            string key = reader.GetString();
            reader.Read();

            using (JsonDocument doc = JsonDocument.ParseValue(ref reader))
            {
                string resourceJson = doc.RootElement.GetRawText();
                Resource resource = _fhirJsonParser.Parse<Resource>(resourceJson);
                prefetch.Add(key, resource);
            }
        }

        throw new JsonException();
    }

    public override void Write(Utf8JsonWriter writer, Dictionary<string, Resource> value, JsonSerializerOptions options)
    {
        var serializerSettings = new SerializerSettings();
        if (options.WriteIndented)
        {
            serializerSettings.Pretty = true;
        }

        writer.WriteStartObject();

        foreach (var kvp in value)
        {
            writer.WritePropertyName(kvp.Key);
            var resourceJson = new FhirJsonSerializer(serializerSettings).SerializeToString(kvp.Value);
            var indentedResourceJson = IndentJson(resourceJson, 2);
            writer.WriteRawValue(indentedResourceJson);
        }

        writer.WriteEndObject();
    }


    private string IndentJson(string json, int additionalIndentationLevels)
    {
        var indentedJson = new StringBuilder();
        var lines = json.Split('\n');
        var additionalIndentation = new string(' ', additionalIndentationLevels * 2); // Assuming 2 spaces per level

        foreach (var line in lines)
        {
            indentedJson.Append(additionalIndentation + line);
        }

        return indentedJson.ToString();
    }
}