using Shye.Configuration;
using Shye.Metrics;
using Shye.Protocols;

namespace Shye.Experiments;

public sealed class ExperimentRunner
{
    #region Private Fields

    private readonly ExperimentConfig _config;
    private readonly int? _seedOverride;

    #endregion

    #region Public Methods

    public ExperimentRunner(ExperimentConfig config, int? seedOverride)
    {
        _config = config;
        _seedOverride = seedOverride;
    }

    public async Task RunAsync()
    {
        var seeds = _seedOverride is { } count
            ? Enumerable.Range(1, Math.Max(1, count)).ToList()
            : _config.Seeds;

        var outputDirectory = Path.Combine(
            _config.Output.Directory,
            $"{Sanitize(_config.Experiment)}_{DateTime.Now:yyyyMMdd_HHmmss}");

        Directory.CreateDirectory(outputDirectory);
        await using var output = new CsvOutput(outputDirectory, _config.Output);

        var runCount = 0;
        var ablationVariants = BuildAblationVariants(_config);
        foreach (var protocol in _config.Protocols)
        {
            var protocolName = protocol.ToLowerInvariant();
            foreach (var ablationVariant in ablationVariants)
            foreach (var topology in _config.Topologies)
            foreach (var nodeCount in _config.Network.NodeCounts)
            foreach (var degree in _config.Network.AverageDegrees)
            foreach (var ttl in _config.Shye.TtlValues)
            foreach (var lossProbability in _config.Network.LossProbabilities)
            foreach (var alpha in _config.Adversary.AlphaValues)
            foreach (var observerMode in _config.Adversary.ObserverModes)
            foreach (var seed in seeds)
            {
                if (protocolName != "shye" && ablationVariant.Name != "full")
                {
                    continue;
                }

                var runConfig = WithAblation(_config, ablationVariant.Ablation);
                var parameters = new RunParameters(
                    RunId: BuildRunId(protocolName, ablationVariant.Name, topology, nodeCount, degree, ttl,
                        lossProbability, alpha, observerMode, seed),
                    Experiment: _config.Experiment,
                    Variant: ablationVariant.Name,
                    Protocol: protocolName,
                    TopologyName: topology,
                    NodeCount: nodeCount,
                    AverageDegree: degree,
                    Ttl: ttl,
                    Seed: seed,
                    LossProbability: lossProbability,
                    Alpha: alpha,
                    ObserverMode: observerMode,
                    Config: runConfig);
                switch (protocolName)
                {
                    case "shye":
                    {
                        new MinimalShyeSimulator(parameters, output).Run();
                        break;
                    }
                    case "fixed_path_onion":
                    case "random_walk":
                    case "flooding":
                    {
                        new BaselineSimulator(parameters, output).Run();
                        break;
                    }
                    default:
                    {
                        Console.WriteLine($"Skipping unsupported protocol: {protocolName}");
                        continue;
                    }
                }

                runCount++;
                Console.WriteLine($"Finished {parameters.RunId}");
            }
        }

        await output.FlushAsync();
        Console.WriteLine();
        Console.WriteLine($"Runs completed: {runCount}");
        Console.WriteLine($"Output directory: {Path.GetFullPath(outputDirectory)}");
    }

    #endregion

    #region Private Methods
    
    private static string BuildRunId(
        string protocol,
        string variant,
        string topology,
        int nodeCount,
        int degree,
        int ttl,
        double lossProbability,
        double alpha,
        string observerMode,
        int seed)
    {
        return Sanitize(
            $"{protocol}_{variant}_{topology}_N{nodeCount}_d{degree}_ttl{ttl}_loss{lossProbability:0.###}_alpha{alpha:0.###}_{observerMode}_seed{seed}");
    }

    private static string Sanitize(string value)
    {
        var chars = value.Select(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' ? ch : '_');
        return new string(chars.ToArray());
    }

    private static List<AblationRunVariant> BuildAblationVariants(ExperimentConfig config)
    {
        if (config.AblationVariants.Count == 0)
        {
            return [new AblationRunVariant("full", config.Ablation.Clone())];
        }

        var variants = new List<AblationRunVariant>();
        foreach (var variant in config.AblationVariants)
        {
            var ablation = config.Ablation.Clone();
            ablation.Apply(variant);
            variants.Add(new AblationRunVariant(Sanitize(variant.Name), ablation));
        }

        return variants;
    }

    private static ExperimentConfig WithAblation(ExperimentConfig source, AblationConfig ablation)
    {
        return new ExperimentConfig
        {
            Experiment = source.Experiment,
            Protocols = source.Protocols,
            Seeds = source.Seeds,
            Topologies = source.Topologies,
            Network = source.Network,
            Traffic = source.Traffic,
            Shye = source.Shye,
            Adversary = source.Adversary,
            Ablation = ablation,
            AblationVariants = source.AblationVariants,
            CryptoCost = source.CryptoCost,
            Output = source.Output
        };
    }

    #endregion
}


internal sealed record AblationRunVariant(string Name, AblationConfig Ablation);

public sealed record RunParameters(
    string RunId,
    string Experiment,
    string Variant,
    string Protocol,
    string TopologyName,
    int NodeCount,
    int AverageDegree,
    int Ttl,
    int Seed,
    double LossProbability,
    double Alpha,
    string ObserverMode,
    ExperimentConfig Config);
