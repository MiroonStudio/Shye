using Shye.Configuration;
using Shye.Experiments;
using Shye.Metrics;

return await Cli.RunAsync(args);

internal static class Cli
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintUsage();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var configPath = ReadOption(args, "--config");
        if (command is "experiment" or "sweep" && string.IsNullOrWhiteSpace(configPath))
        {
            await Console.Error.WriteLineAsync("Missing required option: --config <path>");
            PrintUsage();
            return 2;
        }

        try
        {
            switch (command)
            {
                case "experiment" or "sweep":
                {
                    var config = await ExperimentConfig.LoadAsync(configPath!);
                    var seedOverride = ReadIntOption(args, "--seeds");
                    var runner = new ExperimentRunner(config, seedOverride);
                    await runner.RunAsync();
                    return 0;
                }
                case "summarize" or "summary":
                {
                    var input = ReadOption(args, "--input");
                    var output = ReadOption(args, "--output");
                    if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(output))
                    {
                        Console.Error.WriteLine("Missing required options: --input <run_metrics.csv or directory> --output <summary.csv or directory>");
                        return 2;
                    }

                    await SummaryAggregator.SummarizeAsync(input, output);
                    return 0;
                }
            }

            await Console.Error.WriteLineAsync($"Unknown command: {command}");
            PrintUsage();
            return 2;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.Message);
            return 1;
        }
    }

    private static string? ReadOption(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return null;
    }

    private static int? ReadIntOption(string[] args, string name)
    {
        var value = ReadOption(args, name);
        return int.TryParse(value, out var parsed) ? parsed : null;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Shye experiment simulator");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run -- experiment --config configs/scale.json");
        Console.WriteLine("  dotnet run -- sweep --config configs/scale.json --seeds 30");
        Console.WriteLine("  dotnet run -- summarize --input results/raw/run_metrics.csv --output results/summary/summary.csv");
    }
}
