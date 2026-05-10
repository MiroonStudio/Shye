using Shye.Experiments;
using Shye.Network;
using Shye.Protocols;

namespace Shye.Metrics;

public sealed class MetricsCollector
{
    #region Private Fields

    private readonly RunParameters _parameters;
    private readonly CsvOutput _output;
    private readonly Dictionary<string, MessageState> _messages = new();
    private long _packetArrivals;
    private long _duplicateDrops;
    private long _totalBroadcasts;
    private long _totalBytes;
    private long _winnerCertAttempts;
    private long _winnerCertSuccesses;
    private long _settlementTimeouts;
    private long _winnerSelections;
    private long _maliciousWinnerSelections;
    private long _capturedMessages;
    private long _rendezvousAttempts;
    private long _rendezvousSuccesses;
    private long _sourceIdentificationAttempts;
    private long _sourceIdentificationSuccesses;
    private long _pathLinkingAttempts;
    private long _pathLinkingSuccesses;

    #endregion

    #region Public Methods

     public MetricsCollector(RunParameters parameters, CsvOutput output)
    {
        _parameters = parameters;
        _output = output;
    }

    public void RecordEvent(double timeMs, string type, Node node, Packet? packet, string? detail = null)
    {
        _output.WriteEvent(new EventRecord(
            _parameters.RunId,
            _parameters.Seed,
            timeMs,
            type,
            node.Id,
            packet?.MessageId,
            packet?.PacketId,
            packet?.HopIndex ?? -1,
            packet?.AuctionId,
            packet?.SizeBytes ?? 0,
            packet?.IsCover ?? false,
            node.IsMalicious,
            detail));
    }

    public void RecordSyntheticEvent(double timeMs, string type, Packet? packet, string? detail = null)
    {
        _output.WriteEvent(new EventRecord(
            _parameters.RunId,
            _parameters.Seed,
            timeMs,
            type,
            -1,
            packet?.MessageId,
            packet?.PacketId,
            packet?.HopIndex ?? -1,
            packet?.AuctionId,
            packet?.SizeBytes ?? 0,
            packet?.IsCover ?? false,
            false,
            detail));
    }

    public void RecordPacketArrival()
    {
        _packetArrivals++;
    }

    public void RecordDuplicateDrop()
    {
        _duplicateDrops++;
    }

    public void StartMessage(string messageId, int sourceId, int destinationId, double injectedAtMs)
    {
        _messages[messageId] = new MessageState(messageId, sourceId, destinationId, injectedAtMs);
    }

    public void RecordTransmit(Packet packet)
    {
        _totalBroadcasts++;
        _totalBytes += packet.SizeBytes;

        if (packet.MessageId is null || !_messages.TryGetValue(packet.MessageId, out var message)) return;
        message.TotalBroadcasts++;
        message.TotalBytes += packet.SizeBytes;
    }

    public void MarkDelivered(Packet packet, double timeMs, int nodeId)
    {
        if (packet.MessageId is null || !_messages.TryGetValue(packet.MessageId, out var message))
        {
            return;
        }

        if (message.DeliveredAtMs.HasValue)
        {
            return;
        }

        message.DeliveredAtMs = timeMs;
        message.HopCount = packet.HopIndex;
        message.FailReason = "";
        message.MaliciousWinners = packet.MaliciousWinners;
    }

    public void MarkFailed(Packet packet, string failReason)
    {
        if (packet.MessageId is null || !_messages.TryGetValue(packet.MessageId, out var message))
        {
            return;
        }

        if (message.DeliveredAtMs.HasValue || !string.IsNullOrEmpty(message.FailReason))
        {
            return;
        }

        message.FailReason = failReason;
        message.HopCount = packet.HopIndex;
        message.MaliciousWinners = packet.MaliciousWinners;
    }

    public void RecordWinnerCertAttempt(bool success)
    {
        _winnerCertAttempts++;
        if (success)
        {
            _winnerCertSuccesses++;
        }
        else
        {
            _settlementTimeouts++;
        }
    }

    public void RecordWinnerSelection(Packet packet, Node winner)
    {
        _winnerSelections++;
        if (winner.IsMalicious)
        {
            _maliciousWinnerSelections++;
            if (packet.MaliciousWinners == 0)
            {
                _capturedMessages++;
            }
        }
    }

    public void RecordRendezvousAttempt(bool success)
    {
        _rendezvousAttempts++;
        if (success)
        {
            _rendezvousSuccesses++;
        }
    }

    public void RecordAttackEstimate(Packet packet, bool sourceIdentified, bool pathLinked)
    {
        if (packet.MessageId is null || !_messages.TryGetValue(packet.MessageId, out var message))
        {
            return;
        }

        if (!message.AttackEstimated)
        {
            _sourceIdentificationAttempts++;
            _pathLinkingAttempts++;
            message.AttackEstimated = true;
        }

        message.SourceIdentified = sourceIdentified;
        message.PathLinked = pathLinked;

        if (sourceIdentified)
        {
            _sourceIdentificationSuccesses++;
        }

        if (pathLinked)
        {
            _pathLinkingSuccesses++;
        }
    }

    public void WriteNodeState(double timeMs, IReadOnlyList<Node> nodes)
    {
        foreach (var node in nodes)
        {
            _output.WriteNodeState(new NodeStateOutput(
                _parameters.RunId,
                _parameters.Seed,
                timeMs,
                node.Id,
                node.IsMalicious,
                node.BroadcastSeenCache.Count,
                node.ClaimTable.Count,
                0,
                0,
                0));
        }
    }

    public void Finish()
    {
        foreach (var message in _messages.Values)
        {
            if (!message.DeliveredAtMs.HasValue && string.IsNullOrEmpty(message.FailReason))
            {
                message.FailReason = "not_delivered";
            }

            _output.WriteMessage(new MessageOutput(
                _parameters.RunId,
                _parameters.Seed,
                message.MessageId,
                message.SourceId,
                message.DestinationId,
                _parameters.Protocol,
                _parameters.TopologyName,
                _parameters.NodeCount,
                _parameters.AverageDegree,
                _parameters.Ttl,
                _parameters.Alpha,
                message.InjectedAtMs,
                message.DeliveredAtMs,
                message.DeliveredAtMs.HasValue,
                message.FailReason,
                message.HopCount,
                message.TotalBroadcasts,
                message.TotalBytes,
                message.MaliciousWinners,
                message.SourceIdentified,
                message.PathLinked));
        }

        var delivered = _messages.Values.Where(message => message.DeliveredAtMs.HasValue).ToList();
        var latencies = delivered
            .Select(message => message.DeliveredAtMs!.Value - message.InjectedAtMs)
            .OrderBy(value => value)
            .ToArray();

        var durationSeconds = Math.Max(1e-9, _parameters.Config.Traffic.SimulationDurationMs / 1000.0);
        var deliverySuccessRate = _messages.Count == 0 ? 0.0 : (double)delivered.Count / _messages.Count;
        var duplicateDropRatio = _packetArrivals == 0 ? 0.0 : (double)_duplicateDrops / _packetArrivals;

        var maliciousWinnerRatio = _winnerSelections == 0 ? double.NaN : (double)_maliciousWinnerSelections / _winnerSelections;
        var winnerCertSuccessRate = _winnerCertAttempts == 0 ? double.NaN : (double)_winnerCertSuccesses / _winnerCertAttempts;
        var settlementTimeoutRatio = _winnerCertAttempts == 0 ? double.NaN : (double)_settlementTimeouts / _winnerCertAttempts;
        var pathCaptureProbability = _messages.Count == 0 ? 0.0 : (double)_capturedMessages / _messages.Count;
        var rendezvousDeliverySuccessRate = _rendezvousAttempts == 0 ? 0.0 : (double)_rendezvousSuccesses / _rendezvousAttempts;
        var sourceIdentificationSuccessRate = _sourceIdentificationAttempts == 0 ? double.NaN : (double)_sourceIdentificationSuccesses / _sourceIdentificationAttempts;
        var pathLinkingSuccessRate = _pathLinkingAttempts == 0 ? double.NaN : (double)_pathLinkingSuccesses / _pathLinkingAttempts;

        _output.WriteRunMetrics(new RunMetricsOutput(
            _parameters.RunId,
            _parameters.Seed,
            _parameters.Experiment,
            _parameters.Variant,
            _parameters.Protocol,
            _parameters.TopologyName,
            _parameters.NodeCount,
            _parameters.AverageDegree,
            _parameters.Ttl,
            _parameters.Config.Shye.TauSettleMs,
            _parameters.Config.Traffic.LambdaCover,
            _parameters.Config.Traffic.LambdaMsg,
            _parameters.Alpha,
            _parameters.LossProbability,
            _parameters.ObserverMode,
            _parameters.Config.Adversary.IdentityMultiplier,
            _parameters.Config.Adversary.GrindingAttempts,
            _parameters.Config.Ablation.DisableCommitReveal,
            _parameters.Config.Ablation.DisableLinkProof,
            _parameters.Config.Ablation.DisableRerandomization,
            _parameters.Config.Ablation.EnableStableRouteTag,
            deliverySuccessRate,
            Average(latencies),
            Percentile(latencies, 0.50),
            Percentile(latencies, 0.95),
            delivered.Count / durationSeconds,
            _totalBroadcasts,
            _totalBytes,
            duplicateDropRatio,
            sourceIdentificationSuccessRate,
            pathLinkingSuccessRate,
            pathCaptureProbability,
            maliciousWinnerRatio,
            winnerCertSuccessRate,
            settlementTimeoutRatio,
            rendezvousDeliverySuccessRate));
    }

    #endregion

    #region Private Methods

    private static double Average(double[] values) => values.Length == 0 ? 0.0 : values.Average();

    private static double Percentile(double[] sortedValues, double percentile)
    {
        if (sortedValues.Length == 0) return 0.0;
        if (sortedValues.Length == 1) return sortedValues[0];

        var index = percentile * (sortedValues.Length - 1);
        var lower = (int)Math.Floor(index);
        var upper = (int)Math.Ceiling(index);
        if (lower == upper) return sortedValues[lower];

        var weight = index - lower;
        return sortedValues[lower] * (1.0 - weight) + sortedValues[upper] * weight;
    }

    #endregion
    

    private sealed class MessageState
    {
        public MessageState(string messageId, int sourceId, int destinationId, double injectedAtMs)
        {
            MessageId = messageId;
            SourceId = sourceId;
            DestinationId = destinationId;
            InjectedAtMs = injectedAtMs;
        }

        #region Public Fields

        public string MessageId { get; }
        public int SourceId { get; }
        public int DestinationId { get; }
        public double InjectedAtMs { get; }
        public double? DeliveredAtMs { get; set; }
        public string FailReason { get; set; } = "";
        public int HopCount { get; set; } = -1;
        public long TotalBroadcasts { get; set; }
        public long TotalBytes { get; set; }
        public int MaliciousWinners { get; set; }
        public bool AttackEstimated { get; set; }
        public bool SourceIdentified { get; set; }
        public bool PathLinked { get; set; }

        #endregion
    }
}
