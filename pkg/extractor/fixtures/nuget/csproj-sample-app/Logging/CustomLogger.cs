using Microsoft.Extensions.Logging;
using Serilog;

namespace ExampleCorp.Logging;

public class CustomLogger
{
    private readonly ILogger _logger;

    public CustomLogger(ILogger logger)
    {
        _logger = logger;
    }

    public void LogInfo(string message)
    {
        _logger.LogInformation(message);
    }

    public void LogError(string message, Exception? exception = null)
    {
        _logger.LogError(exception, message);
    }

    public void LogWarning(string message)
    {
        _logger.LogWarning(message);
    }
}