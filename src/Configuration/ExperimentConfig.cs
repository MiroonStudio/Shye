using System.Text.Json;

namespace Shye.Configuration;

public sealed class ExperimentConfig
{
    #region Pubilc Fields
    
    public string Experiment { get; init; } = "scale";
    public List<string> Protocols { get; init; } = ["shye"];
    public List<int> Seeds { get; init; } = [1];
    public List<string> Topologies { get; init; } = ["random"];
    public List<AblationVariantConfig> AblationVariants { get; init; } = [];
    public NetworkConfig Network { get; init; } = new();
    public TrafficConfig Traffic { get; init; } = new();
    public ShyeConfig Shye { get; init; } = new();
    public AdversaryConfig Adversary { get; init; } = new();
    public AblationConfig Ablation { get; init; } = new();
    public CryptoCostConfig CryptoCost { get; init; } = new();
    public OutputConfig Output { get; init; } = new();
    
    #endregion

    #region Public Method

    public static async Task<ExperimentConfig> LoadAsync(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Configuration file not found: {path}");
        }

        await using var stream = File.OpenRead(path);
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        var config = await JsonSerializer.DeserializeAsync<ExperimentConfig>(stream, options);
        if (config is null)
        {
            throw new InvalidOperationException($"Configuration file is empty or could not be parsed: {path}");
        }

        config.Normalize();
        return config;
    }

    #endregion

    #region Private Method
    
    private void Normalize()
    {
        if (Protocols.Count == 0) Protocols.Add("shye");
        if (Seeds.Count == 0) Seeds.Add(1);
        if (Topologies.Count == 0) Topologies.Add("random");
        if (Network.NodeCounts.Count == 0) Network.NodeCounts.Add(100);
        if (Network.AverageDegrees.Count == 0) Network.AverageDegrees.Add(8);
        if (Network.LossProbabilities.Count == 0) Network.LossProbabilities.Add(0.0);
        if (Shye.TtlValues.Count == 0) Shye.TtlValues.Add(7);
        if (Adversary.AlphaValues.Count == 0) Adversary.AlphaValues.Add(0.0);
        if (Adversary.ObserverModes.Count == 0) Adversary.ObserverModes.Add("local");
    }
    
    #endregion
    
}

#region Configs

/// <summary>
/// Network-size, topology, latency, and loss parameters for an experiment sweep.
/// </summary>
public sealed class NetworkConfig
{
    public List<int> NodeCounts { get; set; } = [100];
    public List<int> AverageDegrees { get; set; } = [8];
    public double BaseDelayMs { get; set; } = 20.0;
    public double JitterMs { get; set; } = 10.0;
    public List<double> LossProbabilities { get; set; } = [0.0];
}
/// <summary>
/// Traffic generation and sampling parameters for each simulation run.
/// </summary>
public sealed class TrafficConfig
{
    public double SimulationDurationMs { get; set; } = 60_000.0;
    public double MaxTailMs { get; set; } = 30_000.0;
    public double LambdaMsg { get; set; } = 0.2;
    public double LambdaCover { get; set; } = 0.02;
    public double StateSampleIntervalMs { get; set; } = 5_000.0;
    public int RealPacketBytes { get; set; } = 1024;
    public int CoverPacketBytes { get; set; } = 256;
    public int MaxEvents { get; set; } = 2_000_000;
}
/// <summary>
/// Shye protocol parameters used by the abstract simulator.
/// </summary>
public sealed class ShyeConfig
{
    public List<int> TtlValues { get; set; } = [7];
    public int FloodDepth { get; set; } = 4;
    public double HeartbeatMs { get; set; } = 1_000.0;
    public double TauSettleMs { get; set; } = 200.0;
    public double OverlapWindowMs { get; set; } = 300.0;
    public double CommitRevealDelayMs { get; set; } = 100.0;
    public int WitnessF { get; set; } = 1;
    public int RendezvousF { get; set; } = 1;
}
/// <summary>
/// Adversary and observation parameters used by attack estimators.
/// </summary>
public sealed class AdversaryConfig
{
    public List<double> AlphaValues { get; set; } = [0.0];
    public List<string> ObserverModes { get; set; } = ["local"];
    public double IdentityMultiplier { get; set; } = 1.0;
    public int GrindingAttempts { get; set; } = 1;
    public double MaliciousDropProbability { get; set; } = 0.0;
    public double MaliciousDelayMs { get; set; } = 0.0;
}
/// <summary>
/// Feature switches used to run Shye ablation experiments.
/// </summary>
public sealed class AblationConfig
{
    #region Public Fields

    public bool DisableCommitReveal { get; set; }
    public bool DisableDedup { get; set; }
    public bool DisableWinnerCert { get; set; }
    public bool DisableLinkProof { get; set; }
    public bool DisableRerandomization { get; set; }
    public bool EnableStableRouteTag { get; set; }
    public bool DisableTtl { get; set; }

    #endregion

    #region Public Methods

    public AblationConfig Clone()
    {
        return new AblationConfig
        {
            DisableCommitReveal = DisableCommitReveal,
            DisableDedup = DisableDedup,
            DisableWinnerCert = DisableWinnerCert,
            DisableLinkProof = DisableLinkProof,
            DisableRerandomization = DisableRerandomization,
            EnableStableRouteTag = EnableStableRouteTag,
            DisableTtl = DisableTtl
        };
    }

    public void Apply(AblationVariantConfig variant)
    {
        if (variant.DisableCommitReveal.HasValue) DisableCommitReveal = variant.DisableCommitReveal.Value;
        if (variant.DisableDedup.HasValue) DisableDedup = variant.DisableDedup.Value;
        if (variant.DisableWinnerCert.HasValue) DisableWinnerCert = variant.DisableWinnerCert.Value;
        if (variant.DisableLinkProof.HasValue) DisableLinkProof = variant.DisableLinkProof.Value;
        if (variant.DisableRerandomization.HasValue) DisableRerandomization = variant.DisableRerandomization.Value;
        if (variant.EnableStableRouteTag.HasValue) EnableStableRouteTag = variant.EnableStableRouteTag.Value;
        if (variant.DisableTtl.HasValue) DisableTtl = variant.DisableTtl.Value;
    }

    #endregion
   
}
/// <summary>
/// Overrides for one named ablation variant in a sweep configuration.
/// </summary>
// ReSharper disable once ClassNeverInstantiated.Global
// Instantiated by System.Text.Json during configuration binding.
public sealed record AblationVariantConfig
{
    public string Name { get; set; } = "full";
    public bool? DisableCommitReveal { get; set; }
    public bool? DisableDedup { get; set; }
    public bool? DisableWinnerCert { get; set; }
    public bool? DisableLinkProof { get; set; }
    public bool? DisableRerandomization { get; set; }
    public bool? EnableStableRouteTag { get; set; }
    public bool? DisableTtl { get; set; }
}
/// <summary>
/// Abstract cryptographic cost model used for latency and byte accounting.
/// </summary>
public sealed class CryptoCostConfig
{
    public double WinnerCertVerifyMs { get; set; } = 0.2;
    public int WinnerCertBytes { get; set; } = 96;
    public double LinkProofVerifyMs { get; set; } = 1.0;
    public int LinkProofBytes { get; set; } = 512;
    public double ThresholdDecryptMs { get; set; } = 2.0;
    public int ThresholdDecryptBytes { get; set; } = 256;
    public int ForwarderSignatureBytes { get; set; } = 64;
}
/// <summary>
/// Output settings for raw simulation artifacts.
/// </summary>
public sealed class OutputConfig
{
    public string Directory { get; set; } = "results/raw";
    public bool WriteEvents { get; set; } = true;
    public bool WriteNodeState { get; set; } = true;
}

#endregion
