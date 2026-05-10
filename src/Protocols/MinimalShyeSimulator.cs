using Shye.Adversary;
using Shye.Core;
using Shye.Experiments;
using Shye.Metrics;
using Shye.Network;

namespace Shye.Protocols;

public sealed class MinimalShyeSimulator
{
    #region Private Fields

    private readonly RunParameters _parameters;
    private readonly RandomSource _random;
    private readonly EventQueue _queue = new();
    private readonly MetricsCollector _metrics;
    private readonly AttackEstimator _attackEstimator;
    private readonly Dictionary<string, AuctionRound> _auctions = new(StringComparer.Ordinal);
    private readonly HashSet<string> _settlementScheduled = new(StringComparer.Ordinal);
    private int _messageCounter;
    private int _coverCounter;
    private int _processedEvents;

    #endregion

    #region Public Methods

    public MinimalShyeSimulator(RunParameters parameters, CsvOutput output)
    {
        _parameters = parameters;
        _random = new RandomSource(parameters.Seed);
        _metrics = new MetricsCollector(parameters, output);
        _attackEstimator = new AttackEstimator(parameters);
    }

    public void Run()
    {
        var topologyRandom = new RandomSource(_random.StableFork("topology"));
        var topology = TopologyGenerator.Generate(
            _parameters.TopologyName,
            _parameters.NodeCount,
            _parameters.AverageDegree,
            _parameters.Alpha,
            topologyRandom);

        ScheduleTraffic(topology);
        ScheduleStateSamples();

        var maxTime = _parameters.Config.Traffic.SimulationDurationMs + _parameters.Config.Traffic.MaxTailMs;
        while (_queue.TryDequeue(out var simulationEvent))
        {
            if (simulationEvent.TimeMs > maxTime)
            {
                break;
            }

            _processedEvents++;
            if (_processedEvents > _parameters.Config.Traffic.MaxEvents)
            {
                _metrics.RecordSyntheticEvent(simulationEvent.TimeMs, "MaxEventsReached", null, "run stopped by max event guard");
                break;
            }

            HandleEvent(simulationEvent, topology);
        }

        _metrics.Finish();
    }

    #endregion

    #region Private Methods

     private void ScheduleTraffic(Topology topology)
    {
        var durationMs = _parameters.Config.Traffic.SimulationDurationMs;

        var nextMessageTime = _random.NextExponentialSeconds(_parameters.Config.Traffic.LambdaMsg) * 1000.0;
        while (nextMessageTime <= durationMs)
        {
            var source = _random.NextInt(_parameters.NodeCount);
            var destination = PickDifferentNode(source);
            _queue.Enqueue(new SimulationEvent(
                nextMessageTime,
                SimulationEventType.MessageInject,
                NodeId: source,
                DestinationNodeId: destination));
            nextMessageTime += _random.NextExponentialSeconds(_parameters.Config.Traffic.LambdaMsg) * 1000.0;
        }

        var coverRate = _parameters.Config.Traffic.LambdaCover;
        if (coverRate <= 0.0) return;

        foreach (var node in topology.Nodes)
        {
            var nextCoverTime = _random.NextExponentialSeconds(coverRate) * 1000.0;
            while (nextCoverTime <= durationMs)
            {
                _queue.Enqueue(new SimulationEvent(
                    nextCoverTime,
                    SimulationEventType.CoverInject,
                    NodeId: node.Id));
                nextCoverTime += _random.NextExponentialSeconds(coverRate) * 1000.0;
            }
        }
    }

    private void ScheduleStateSamples()
    {
        var interval = Math.Max(1.0, _parameters.Config.Traffic.StateSampleIntervalMs);
        var maxTime = _parameters.Config.Traffic.SimulationDurationMs + _parameters.Config.Traffic.MaxTailMs;
        for (var time = 0.0; time <= maxTime; time += interval)
        {
            _queue.Enqueue(new SimulationEvent(time, SimulationEventType.StateSample));
        }
    }

    private void HandleEvent(SimulationEvent simulationEvent, Topology topology)
    {
        switch (simulationEvent.Type)
        {
            case SimulationEventType.MessageInject:
                HandleMessageInject(simulationEvent, topology);
                break;
            case SimulationEventType.CoverInject:
                HandleCoverInject(simulationEvent, topology);
                break;
            case SimulationEventType.ForwardStart:
                HandleForwardStart(simulationEvent, topology);
                break;
            case SimulationEventType.PacketArrive:
                HandlePacketArrive(simulationEvent, topology);
                break;
            case SimulationEventType.AuctionSettle:
                HandleAuctionSettle(simulationEvent, topology);
                break;
            case SimulationEventType.RendezvousDeliver:
                HandleRendezvousDeliver(simulationEvent, topology);
                break;
            case SimulationEventType.StateSample:
                _metrics.WriteNodeState(simulationEvent.TimeMs, topology.Nodes);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(simulationEvent.Type), simulationEvent.Type, "Unknown event type.");
        }
    }

    private void HandleMessageInject(SimulationEvent simulationEvent, Topology topology)
    {
        var source = topology.Nodes[simulationEvent.NodeId];
        var messageId = $"m{_messageCounter++}";
        var packet = new Packet(
            PacketId: $"p-{messageId}-h0",
            MessageId: messageId,
            SourceNodeId: source.Id,
            IsCover: false,
            RemainingTtl: _parameters.Ttl,
            HopIndex: 0,
            FloodDepthRemaining: _parameters.Config.Shye.FloodDepth,
            SizeBytes: RealPacketSize(),
            AuctionId: $"a-{messageId}-h0",
            MaliciousWinners: 0);

        _metrics.StartMessage(messageId, source.Id, simulationEvent.DestinationNodeId, simulationEvent.TimeMs);
        _metrics.RecordEvent(simulationEvent.TimeMs, "CommitEph", source, packet);

        var revealDelay = _parameters.Config.Ablation.DisableCommitReveal
            ? 0.0
            : Math.Max(0.0, _parameters.Config.Shye.CommitRevealDelayMs);

        _queue.Enqueue(new SimulationEvent(
            simulationEvent.TimeMs + revealDelay,
            SimulationEventType.ForwardStart,
            NodeId: source.Id,
            Packet: packet));
    }

    private void HandleCoverInject(SimulationEvent simulationEvent, Topology topology)
    {
        var source = topology.Nodes[simulationEvent.NodeId];
        var coverId = $"c{_coverCounter++}";
        var packet = new Packet(
            PacketId: $"cover-{coverId}",
            MessageId: null,
            SourceNodeId: source.Id,
            IsCover: true,
            RemainingTtl: 0,
            HopIndex: 0,
            FloodDepthRemaining: Math.Max(1, Math.Min(_parameters.Config.Shye.FloodDepth, 3)),
            SizeBytes: _parameters.Config.Traffic.CoverPacketBytes,
            AuctionId: $"cover-auction-{coverId}",
            MaliciousWinners: 0);

        _metrics.RecordEvent(simulationEvent.TimeMs, "CoverInject", source, packet);
        _queue.Enqueue(new SimulationEvent(
            simulationEvent.TimeMs,
            SimulationEventType.PacketArrive,
            NodeId: source.Id,
            PreviousNodeId: -1,
            Packet: packet));
    }

    private void HandleForwardStart(SimulationEvent simulationEvent, Topology topology)
    {
        if (simulationEvent.Packet is null) return;

        var packet = simulationEvent.Packet;
        var forwarder = topology.Nodes[simulationEvent.NodeId];
        var packetForHop = packet with
        {
            FloodDepthRemaining = Math.Max(0, _parameters.Config.Shye.FloodDepth),
            PacketId = $"p-{packet.MessageId}-h{packet.HopIndex}-{packet.AuctionId}",
            SizeBytes = RealPacketSize()
        };

        _metrics.RecordEvent(simulationEvent.TimeMs, "ForwardStart", forwarder, packetForHop);

        if (!packetForHop.IsCover)
        {
            EnsureAuction(packetForHop, simulationEvent.TimeMs);
            ScheduleAuctionSettle(packetForHop, simulationEvent.TimeMs);
        }

        _queue.Enqueue(new SimulationEvent(
            simulationEvent.TimeMs,
            SimulationEventType.PacketArrive,
            NodeId: forwarder.Id,
            PreviousNodeId: -1,
            Packet: packetForHop));
    }

    private void HandlePacketArrive(SimulationEvent simulationEvent, Topology topology)
    {
        if (simulationEvent.Packet is null) return;

        var packet = simulationEvent.Packet;
        var node = topology.Nodes[simulationEvent.NodeId];
        _metrics.RecordPacketArrival();
        _metrics.RecordEvent(simulationEvent.TimeMs, "PacketArrive", node, packet);

        if (!_parameters.Config.Ablation.DisableDedup)
        {
            var seenKey = $"{packet.PacketId}@{packet.AuctionId}";
            if (!node.BroadcastSeenCache.Add(seenKey))
            {
                _metrics.RecordDuplicateDrop();
                _metrics.RecordEvent(simulationEvent.TimeMs, "DuplicateDrop", node, packet);
                return;
            }
        }

        if (packet.IsCover)
        {
            FloodToNeighbors(simulationEvent, topology, packet);
            return;
        }

        var auction = EnsureAuction(packet, simulationEvent.TimeMs);
        var score = node.IsMalicious
            ? ComputeMaliciousScore(packet.AuctionId, node.Id, packet.HopIndex)
            : ComputeScore(packet.AuctionId, node.Id, packet.HopIndex);
        node.ClaimTable.Add(packet.AuctionId);
        auction.AddCandidate(new AuctionCandidate(node.Id, score));
        _metrics.RecordEvent(simulationEvent.TimeMs, "AuctionClaim", node, packet, $"score={score:0.000000}");

        FloodToNeighbors(simulationEvent, topology, packet);
    }

    private void HandleAuctionSettle(SimulationEvent simulationEvent, Topology topology)
    {
        if (simulationEvent.Packet is null) return;

        var packet = simulationEvent.Packet;
        if (!_auctions.TryGetValue(packet.AuctionId, out var auction) || auction.IsSettled)
        {
            return;
        }

        auction.IsSettled = true;
        if (auction.Candidates.Count == 0)
        {
            _metrics.RecordWinnerCertAttempt(success: false);
            _metrics.MarkFailed(packet, "no_auction_candidates");
            _metrics.RecordSyntheticEvent(simulationEvent.TimeMs, "AuctionTimeout", packet, "no candidates");
            return;
        }

        var winner = auction.Candidates
            .OrderBy(candidate => candidate.Score)
            .ThenBy(candidate => candidate.NodeId)
            .First();

        var winnerNode = topology.Nodes[winner.NodeId];
        var certSuccess = _parameters.Config.Ablation.DisableWinnerCert || CanFormWinnerCert(topology, packet.AuctionId);
        _metrics.RecordWinnerCertAttempt(certSuccess);

        if (!certSuccess)
        {
            RecordAttackEstimate(packet);
            _metrics.MarkFailed(packet, "winner_cert_timeout");
            _metrics.RecordEvent(simulationEvent.TimeMs, "WinnerCertTimeout", winnerNode, packet);
            return;
        }

        _metrics.RecordWinnerSelection(packet, winnerNode);
        _metrics.RecordEvent(simulationEvent.TimeMs, "WinnerCertified", winnerNode, packet, $"score={winner.Score:0.000000}");

        var nextMaliciousWinners = packet.MaliciousWinners + (winnerNode.IsMalicious ? 1 : 0);
        var nextRemainingTtl = _parameters.Config.Ablation.DisableTtl ? packet.RemainingTtl : packet.RemainingTtl - 1;
        var nextHop = packet.HopIndex + 1;

        var certifiedPacket = packet with
        {
            RemainingTtl = nextRemainingTtl,
            HopIndex = nextHop,
            FloodDepthRemaining = _parameters.Config.Shye.FloodDepth,
            MaliciousWinners = nextMaliciousWinners
        };

        if (!_parameters.Config.Ablation.DisableTtl && nextRemainingTtl <= 0)
        {
            _queue.Enqueue(new SimulationEvent(
                simulationEvent.TimeMs + _parameters.Config.CryptoCost.ThresholdDecryptMs,
                SimulationEventType.RendezvousDeliver,
                NodeId: winnerNode.Id,
                Packet: certifiedPacket));
            return;
        }

        if (nextHop >= MaxHopGuard())
        {
            RecordAttackEstimate(certifiedPacket);
            _metrics.MarkFailed(certifiedPacket, "hop_guard_reached");
            _metrics.RecordEvent(simulationEvent.TimeMs, "HopGuardDrop", winnerNode, certifiedPacket);
            return;
        }

        var nextAuctionId = $"{packet.AuctionId}-next-{StableDigest(packet.AuctionId, winnerNode.Id, nextHop)}";
        var nextPacket = certifiedPacket with
        {
            PacketId = $"p-{packet.MessageId}-h{nextHop}-{nextAuctionId}",
            AuctionId = nextAuctionId,
            SizeBytes = RealPacketSize()
        };

        _queue.Enqueue(new SimulationEvent(
            simulationEvent.TimeMs + _parameters.Config.CryptoCost.WinnerCertVerifyMs,
            SimulationEventType.ForwardStart,
            NodeId: winnerNode.Id,
            Packet: nextPacket));
    }

    private void HandleRendezvousDeliver(SimulationEvent simulationEvent, Topology topology)
    {
        if (simulationEvent.Packet is null) return;

        var packet = simulationEvent.Packet;
        var node = topology.Nodes[simulationEvent.NodeId];
        var success = CanRendezvousDeliver(topology, packet.AuctionId);
        _metrics.RecordRendezvousAttempt(success);

        if (success)
        {
            RecordAttackEstimate(packet);
            _metrics.MarkDelivered(packet, simulationEvent.TimeMs, node.Id);
            _metrics.RecordEvent(simulationEvent.TimeMs, "RendezvousDelivered", node, packet);
        }
        else
        {
            RecordAttackEstimate(packet);
            _metrics.MarkFailed(packet, "rendezvous_unavailable");
            _metrics.RecordEvent(simulationEvent.TimeMs, "RendezvousFailed", node, packet);
        }
    }

    private void FloodToNeighbors(SimulationEvent simulationEvent, Topology topology, Packet packet)
    {
        if (packet.FloodDepthRemaining <= 0)
        {
            return;
        }

        var node = topology.Nodes[simulationEvent.NodeId];
        foreach (var neighborId in topology.Neighbors[node.Id])
        {
            if (neighborId == simulationEvent.PreviousNodeId)
            {
                continue;
            }

            if (_random.Chance(_parameters.LossProbability))
            {
                _metrics.RecordEvent(simulationEvent.TimeMs, "PacketLost", node, packet, $"to={neighborId}");
                continue;
            }

            if (node.IsMalicious && _random.Chance(_parameters.Config.Adversary.MaliciousDropProbability))
            {
                _metrics.RecordEvent(simulationEvent.TimeMs, "MaliciousDrop", node, packet, $"to={neighborId}");
                continue;
            }

            var delay = _parameters.Config.Network.BaseDelayMs
                + _random.NextDouble() * _parameters.Config.Network.JitterMs
                + (node.IsMalicious ? _parameters.Config.Adversary.MaliciousDelayMs : 0.0);
            var nextPacket = packet with
            {
                FloodDepthRemaining = packet.FloodDepthRemaining - 1
            };

            _metrics.RecordTransmit(nextPacket);
            _queue.Enqueue(new SimulationEvent(
                simulationEvent.TimeMs + delay,
                SimulationEventType.PacketArrive,
                NodeId: neighborId,
                PreviousNodeId: node.Id,
                Packet: nextPacket));
        }
    }

    private AuctionRound EnsureAuction(Packet packet, double startTimeMs)
    {
        if (_auctions.TryGetValue(packet.AuctionId, out var auction))
        {
            return auction;
        }

        auction = new AuctionRound(packet.AuctionId, packet.MessageId, packet.HopIndex, startTimeMs);
        _auctions.Add(packet.AuctionId, auction);
        return auction;
    }

    private void ScheduleAuctionSettle(Packet packet, double nowMs)
    {
        if (!_settlementScheduled.Add(packet.AuctionId))
        {
            return;
        }

        _queue.Enqueue(new SimulationEvent(
            nowMs + Math.Max(0.0, _parameters.Config.Shye.TauSettleMs),
            SimulationEventType.AuctionSettle,
            Packet: packet));
    }

    private bool CanFormWinnerCert(Topology topology, string auctionId)
    {
        var f = Math.Max(0, _parameters.Config.Shye.WitnessF);
        var n = Math.Min(topology.Nodes.Count, 3 * f + 1);
        if (n == 0) return false;

        var q = Math.Min(n, 2 * f + 1);
        var witnesses = SelectCommittee(topology, auctionId, n);
        var honest = witnesses.Count(node => !node.IsMalicious);
        return honest >= q;
    }

    private bool CanRendezvousDeliver(Topology topology, string auctionId)
    {
        var f = Math.Max(0, _parameters.Config.Shye.RendezvousF);
        var n = Math.Min(topology.Nodes.Count, 3 * f + 1);
        if (n == 0) return false;

        var threshold = Math.Min(n, 2 * f + 1);
        var committee = SelectCommittee(topology, $"rv-{auctionId}", n);
        var honest = committee.Count(node => !node.IsMalicious);
        return honest >= threshold;
    }

    private List<Node> SelectCommittee(Topology topology, string seed, int count)
    {
        return topology.Nodes
            .OrderBy(node => StableDigest(seed, node.Id, _parameters.Seed))
            .Take(count)
            .ToList();
    }

    private double ComputeScore(string auctionId, int nodeId, int hopIndex)
    {
        var digest = StableDigest(auctionId, nodeId, hopIndex);
        return digest / (double)uint.MaxValue;
    }

    private double ComputeMaliciousScore(string auctionId, int nodeId, int hopIndex)
    {
        var attempts = Math.Max(1, _parameters.Config.Adversary.GrindingAttempts);
        var identities = Math.Max(1, (int)Math.Round(_parameters.Config.Adversary.IdentityMultiplier));
        var best = double.MaxValue;

        for (var identity = 0; identity < identities; identity++)
        {
            for (var attempt = 0; attempt < attempts; attempt++)
            {
                var digest = StableDigest($"{auctionId}:sybil:{identity}:grind:{attempt}", nodeId, hopIndex);
                best = Math.Min(best, digest / (double)uint.MaxValue);
            }
        }

        return best;
    }

    private void RecordAttackEstimate(Packet packet)
    {
        if (packet.MessageId is null)
        {
            return;
        }

        var estimate = _attackEstimator.Estimate(packet);
        _metrics.RecordAttackEstimate(packet, estimate.SourceIdentified, estimate.PathLinked);
    }

    private static uint StableDigest(string value, int a, int b)
    {
        unchecked
        {
            var hash = 2166136261u;
            foreach (var ch in value)
            {
                hash ^= ch;
                hash *= 16777619u;
            }

            hash ^= (uint)a;
            hash *= 16777619u;
            hash ^= (uint)b;
            hash *= 16777619u;
            return hash;
        }
    }

    private int RealPacketSize()
    {
        return _parameters.Config.Traffic.RealPacketBytes
            + _parameters.Config.CryptoCost.WinnerCertBytes
            + _parameters.Config.CryptoCost.LinkProofBytes
            + _parameters.Config.CryptoCost.ForwarderSignatureBytes;
    }

    private int PickDifferentNode(int source)
    {
        if (_parameters.NodeCount <= 1) return source;

        var destination = _random.NextInt(_parameters.NodeCount - 1);
        return destination >= source ? destination + 1 : destination;
    }

    private int MaxHopGuard()
    {
        return !_parameters.Config.Ablation.DisableTtl ? Math.Max(1, _parameters.Ttl) : Math.Max(8, Math.Min(64, _parameters.NodeCount * 2));
    }

    #endregion
   
}

public sealed record Packet(
    string PacketId,
    string? MessageId,
    int SourceNodeId,
    bool IsCover,
    int RemainingTtl,
    int HopIndex,
    int FloodDepthRemaining,
    int SizeBytes,
    string AuctionId,
    int MaliciousWinners);

internal sealed class AuctionRound
{
    public AuctionRound(string auctionId, string? messageId, int hopIndex, double startTimeMs)
    {
        AuctionId = auctionId;
        MessageId = messageId;
        HopIndex = hopIndex;
        StartTimeMs = startTimeMs;
    }

    public string AuctionId { get; }
    public string? MessageId { get; }
    public int HopIndex { get; }
    public double StartTimeMs { get; }
    public bool IsSettled { get; set; }
    public List<AuctionCandidate> Candidates { get; } = [];

    public void AddCandidate(AuctionCandidate candidate)
    {
        if (Candidates.All(existing => existing.NodeId != candidate.NodeId))
        {
            Candidates.Add(candidate);
        }
    }
}

internal sealed record AuctionCandidate(int NodeId, double Score);
