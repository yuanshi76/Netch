using System.Text.Json;
using System.Text.Json.Serialization;
using Netch.Enums;
using Netch.Models;
using Netch.Utils;

namespace Netch.JsonConverter;

public class ServerConverterWithTypeDiscriminator : JsonConverter<Server>
{
    public override Server Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var jsonElement = JsonSerializer.Deserialize<JsonElement>(ref reader);
        if (!jsonElement.TryGetProperty("ConfigType", out var configTypeElement))
        {
            throw new JsonException("Server item missing ConfigType.");
        }

        var typeName = configTypeElement.ValueKind switch
        {
            JsonValueKind.String => configTypeElement.GetString(),
            JsonValueKind.Number when configTypeElement.TryGetInt32(out var value) => Enum.GetName(typeof(EConfigType), value),
            _ => null
        };

        if (typeName.IsNullOrWhiteSpace())
        {
            throw new JsonException($"Unsupported server ConfigType: {configTypeElement}");
        }

        var type = ServerHelper.GetTypeByTypeName(typeName);
        return (Server)jsonElement.Deserialize(type)!;
    }

    public override void Write(Utf8JsonWriter writer, Server value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize<object>(writer, value, options);
    }
}
