using Shye.Core;
using Shye.Experiments;
using Shye.Protocols;

namespace Shye.Adversary;

public sealed class AttackEstimator
{
    #region Private Fields

    private readonly RunParameters _parameters;
    private readonly RandomSource _random;

    #endregion

    #region Public Methods

    public AttackEstimator(RunParameters parameters)
    {
        _parameters = parameters;
        _random = new RandomSource(parameters.Seed ^ 0x5A17AC);
    }

    public AttackEstimate Estimate(Packet packet)
    {
        var sourceProbability = EstimateSourceIdentificationProbability(packet);
        var linkProbability = EstimatePathLinkingProbability(packet);
        return new AttackEstimate(
            SourceIdentified: _random.Chance(sourceProbability),
            PathLinked: _random.Chance(linkProbability));
    }

    #endregion

    #region Private Methods

    private double EstimateSourceIdentificationProbability(Packet packet)
    {
        var observation = ObserverCoverage();
        var coverSuppression = 1.0 / (1.0 + _parameters.Config.Traffic.LambdaCover * Math.Max(1, _parameters.NodeCount) * 0.8);
        var commitRevealSuppression = _parameters.Config.Ablation.DisableCommitReveal ? 1.35 : 0.75;
        var protocolMultiplier = _parameters.Protocol switch
        {
            "shye" => 0.55,
            "flooding" => 0.70,
            "random_walk" => 0.95,
            "fixed_path_onion" => 0.90,
            _ => 1.0
        };

        var capturedBoost = packet.MaliciousWinners > 0 ? 1.35 : 1.0;
        var stableTagBoost = _parameters.Config.Ablation.EnableStableRouteTag ? 1.40 : 1.0;
        var probability = observation * coverSuppression * commitRevealSuppression * protocolMultiplier * capturedBoost * stableTagBoost;
        return ClampProbability(probability);
    }

    private double EstimatePathLinkingProbability(Packet packet)
    {
        var observation = ObserverCoverage();
        var ttlExposure = Math.Min(1.0, Math.Max(1, packet.HopIndex) / 7.0);
        var rerandomizationSuppression = _parameters.Protocol == "shye" ? 0.35 : 0.85;
        var linkProofSuppression = _parameters.Protocol == "shye" ? 0.75 : 1.0;

        if (_parameters.Config.Ablation.DisableRerandomization)
        {
            rerandomizationSuppression = 1.25;
        }

        if (_parameters.Config.Ablation.DisableLinkProof)
        {
            linkProofSuppression = 1.20;
        }

        if (_parameters.Config.Ablation.EnableStableRouteTag)
        {
            rerandomizationSuppression = 1.75;
        }

        var capturedBoost = packet.MaliciousWinners > 0 ? 1.45 : 1.0;
        var probability = observation * ttlExposure * rerandomizationSuppression * linkProofSuppression * capturedBoost;
        return ClampProbability(probability);
    }

    private double ObserverCoverage()
    {
        var baseCoverage = _parameters.ObserverMode.ToLowerInvariant() switch
        {
            "local" => 0.08,
            "regional" => 0.22,
            "broad" => 0.45,
            "near_global" => 0.78,
            "global" => 0.95,
            _ => 0.12
        };

        return ClampProbability(baseCoverage + _parameters.Alpha * 0.65);
    }

    private static double ClampProbability(double value)
    {
        return double.IsNaN(value) ? 0.0 : Math.Clamp(value, 0.0, 1.0);
    }

    #endregion
}

public sealed record AttackEstimate(
    bool SourceIdentified,
    bool PathLinked);
