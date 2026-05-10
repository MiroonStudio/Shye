using System.Globalization;
using System.Text;

namespace Shye.Metrics;

public static class SummaryAggregator
{
    #region Private Fields

    private static readonly string[] GroupColumns =
    [
        "experiment",
        "variant",
        "protocol",
        "topology",
        "N",
        "d",
        "ttl",
        "tau_settle",
        "lambda_cover",
        "lambda_msg",
        "alpha",
        "p_loss",
        "observer_mode",
        "identity_multiplier",
        "grinding_attempts",
        "disable_commit_reveal",
        "disable_link_proof",
        "disable_rerandomization",
        "enable_stable_route_tag"
    ];

    private static readonly string[] MetricColumns =
    [
        "delivery_success_rate",
        "latency_avg_ms",
        "latency_p50_ms",
        "latency_p95_ms",
        "throughput_msg_per_sec",
        "total_broadcasts",
        "total_bytes",
        "duplicate_drop_ratio",
        "source_identification_success_rate",
        "path_linking_success_rate",
        "path_capture_probability",
        "malicious_winner_ratio",
        "winner_cert_success_rate",
        "settlement_timeout_ratio",
        "rendezvous_delivery_success_rate"
    ];

    #endregion

    #region Public Method

     public static async Task SummarizeAsync(string inputPath, string outputPath)
    {
        var inputFile = ResolveInputFile(inputPath);
        var outputFile = ResolveOutputFile(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputFile)!);

        var rows = await ReadCsvAsync(inputFile);
        var groups = rows.GroupBy(BuildGroupKey);

        await using var writer = new StreamWriter(outputFile, append: false, new UTF8Encoding(false));
        await writer.WriteLineAsync(string.Join(',', GroupColumns) + ",metric,mean,stddev,ci95_low,ci95_high,sample_count");

        foreach (var group in groups.OrderBy(group => group.Key))
        {
            var first = group.First();
            foreach (var metric in MetricColumns)
            {
                var values = group
                    .Select(row => ParseDouble(row.GetValueOrDefault(metric)))
                    .Where(value => !double.IsNaN(value) && !double.IsInfinity(value))
                    .ToArray();

                if (values.Length == 0)
                {
                    continue;
                }

                var mean = values.Average();
                var stddev = StandardDeviation(values, mean);
                var ci = values.Length <= 1 ? 0.0 : 1.96 * stddev / Math.Sqrt(values.Length);
                var low = mean - ci;
                var high = mean + ci;
                if (IsRatioMetric(metric))
                {
                    low = Math.Clamp(low, 0.0, 1.0);
                    high = Math.Clamp(high, 0.0, 1.0);
                }

                var columns = GroupColumns
                    .Select(column => Escape(first.GetValueOrDefault(column) ?? ""))
                    .Concat([
                        Escape(metric),
                        Format(mean),
                        Format(stddev),
                        Format(low),
                        Format(high),
                        values.Length.ToString(CultureInfo.InvariantCulture)
                    ]);

                await writer.WriteLineAsync(string.Join(',', columns));
            }
        }

        Console.WriteLine($"Summary written: {Path.GetFullPath(outputFile)}");
    }

    #endregion

    #region Private Methods

     private static string ResolveInputFile(string inputPath)
    {
        if (File.Exists(inputPath))
        {
            return inputPath;
        }

        if (!Directory.Exists(inputPath)) throw new FileNotFoundException($"run_metrics.csv not found: {inputPath}");
        var runMetrics = Path.Combine(inputPath, "run_metrics.csv");
        return File.Exists(runMetrics) ? runMetrics : throw new FileNotFoundException($"run_metrics.csv not found: {inputPath}");
    }

    private static string ResolveOutputFile(string outputPath)
    {
        return Path.GetExtension(outputPath).Equals(".csv", StringComparison.OrdinalIgnoreCase) ? outputPath : Path.Combine(outputPath, "summary.csv");
    }

    private static string BuildGroupKey(Dictionary<string, string> row)
    {
        return string.Join('\u001f', GroupColumns.Select(column => row.GetValueOrDefault(column) ?? ""));
    }

    private static async Task<List<Dictionary<string, string>>> ReadCsvAsync(string path)
    {
        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var headerLine = await reader.ReadLineAsync();
        if (headerLine is null)
        {
            return [];
        }

        var headers = ParseCsvLine(headerLine);
        var rows = new List<Dictionary<string, string>>();
        while (await reader.ReadLineAsync() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var values = ParseCsvLine(line);
            var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < headers.Count; i++)
            {
                row[headers[i]] = i < values.Count ? values[i] : "";
            }

            rows.Add(row);
        }

        return rows;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var result = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            switch (ch)
            {
                case '"' when inQuotes && i + 1 < line.Length && line[i + 1] == '"':
                {
                    current.Append('"');
                    i++;
                    break;
                }
                case '"':
                {
                    inQuotes = !inQuotes;
                    break;
                }
                case ',' when !inQuotes:
                {
                    result.Add(current.ToString());
                    current.Clear();
                    break;
                }
                default:
                {
                    current.Append(ch);
                    break;
                }
            }
        }

        result.Add(current.ToString());
        return result;
    }

    private static double ParseDouble(string? value)
    {
        return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : double.NaN;
    }

    private static double StandardDeviation(double[] values, double mean)
    {
        if (values.Length <= 1)
        {
            return 0.0;
        }

        var variance = values.Sum(value => Math.Pow(value - mean, 2)) / (values.Length - 1);
        return Math.Sqrt(variance);
    }

    private static bool IsRatioMetric(string metric)
    {
        return metric.EndsWith("_rate", StringComparison.OrdinalIgnoreCase)
            || metric.EndsWith("_ratio", StringComparison.OrdinalIgnoreCase)
            || metric.EndsWith("_probability", StringComparison.OrdinalIgnoreCase);
    }

    private static string Format(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value)) return "";
        return value.ToString("0.######", CultureInfo.InvariantCulture);
    }

    private static string Escape(string value)
    {
        if (!value.Contains(',') && !value.Contains('"') && !value.Contains('\n') && !value.Contains('\r'))
        {
            return value;
        }

        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    #endregion
   
}
