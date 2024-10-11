#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

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
        throw new NotImplementedException();
    }
}
