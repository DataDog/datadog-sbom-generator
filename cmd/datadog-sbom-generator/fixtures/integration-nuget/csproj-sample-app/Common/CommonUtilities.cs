namespace ExampleCorp.Common;

public static class CommonUtilities
{
    public static string FormatMessage(string message)
    {
        return $"[COMMON] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} - {message}";
    }

    public static T DeepClone<T>(T obj) where T : class
    {
        var json = System.Text.Json.JsonSerializer.Serialize(obj);
        return System.Text.Json.JsonSerializer.Deserialize<T>(json) ?? throw new InvalidOperationException("Failed to deserialize object");
    }
}