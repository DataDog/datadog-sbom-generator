using ExampleCorp.Common;
using ExampleCorp.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

var app = builder.Build();

// Configure the HTTP request pipeline
app.MapGet("/", () =>
{
    var message = CommonUtilities.FormatMessage("Hello World from SampleApp!");
    var data = new { Message = message, Timestamp = DateTime.UtcNow };
    return JsonConvert.SerializeObject(data);
});

app.MapGet("/health", (ILogger<Program> logger) =>
{
    var customLogger = new CustomLogger(logger);
    customLogger.LogInfo("Health check requested");
    return Results.Ok(new { Status = "Healthy", Version = "1.0.0" });
});

app.Run();