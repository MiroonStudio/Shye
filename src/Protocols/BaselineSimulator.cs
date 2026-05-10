using Shye.Adversary;
using Shye.Core;
using Shye.Experiments;
using Shye.Metrics;
using Shye.Network;

namespace Shye.Protocols;

public sealed class BaselineSimulator
{
    
    #region Private Fields

    private readonly RunParameters _parameters;
    private readonly RandomSource _random;
    private readonly MetricsCollector _metrics;
    private readonly AttackEstimator _attackEstimator;
    private int _messageCounter;

    #endregion

    #region Public Methods

    public BaselineSimulator(RunParameters parameters, CsvOutput output)
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

        var durationMs = _parameters.Config.Traffic.SimulationDurationMs;
        var nextMessageTime = _random.NextExponentialSeconds(_parameters.Config.Traffic.LambdaMsg) * 1000.0;
        while (nextMessageTime <= durationMs)
        {
            var source = _random.NextInt(_parameters.NodeCount);
            var destination = PickDifferentNode(source);
            SimulateMessage(topology, nextMessageTime, source, destination);
            nextMessageTime += _random.NextExponentialSeconds(_parameters.Config.Traffic.LambdaMsg) * 1000.0;
        }

        WriteStateSamples(topology);
        _metrics.Finish();
    }

    #endregion

    #region Private Methods

     private void SimulateMessage(Topology topology, double injectedAtMs, int sourceId, int destinationId)
    {
        var messageId = $"m{_messageCounter++}";
        var source = topology.Nodes[sourceId];
        var packet = new Packet(
            PacketId: $"baseline-{_parameters.Protocol}-{messageId}",
            MessageId: messageId,
            SourceNodeId: sourceId,
            IsCover: false,
            RemainingTtl: _parameters.Ttl,
            HopIndex: 0,
            FloodDepthRemaining: _parameters.Config.Shye.FloodDepth,
            SizeBytes: BaselinePacketSize(),
            AuctionId: $"baseline-{messageId}",
            MaliciousWinners: 0);

        _metrics.StartMessage(messageId, sourceId, destinationId, injectedAtMs);
        _metrics.RecordEvent(injectedAtMs, "MessageInject", source, packet);

        switch (_parameters.Protocol)
        {
            case "fixed_path_onion":
                SimulateFixedPath(topology, injectedAtMs, packet);
                break;
            case "random_walk":
                SimulateRandomWalk(topology, injectedAtMs, packet);
                break;
            case "flooding":
                SimulateFlooding(topology, injectedAtMs, packet);
                break;
            default:
                _metrics.MarkFailed(packet, $"unsupported_protocol:{_parameters.Protocol}");
                break;
        }
    }

    private void SimulateFixedPath(Topology topology, double startTimeMs, Packet packet)
    {
        var currentNodeId = packet.SourceNodeId;
        var timeMs = startTimeMs;
        var currentPacket = packet;

        for (var hop = 1; hop <= Math.Max(1, _parameters.Ttl); hop++)
        {
            var nextNodeId = PickGlobalRelay(topology, currentNodeId);
            var nextNode = topology.Nodes[nextNodeId];
            if (_random.Chance(_parameters.LossProbability))
            {
                RecordAttackEstimate(currentPacket);
                _metrics.MarkFailed(currentPacket, "path_link_lost");
                _metrics.RecordEvent(timeMs, "PacketLost", topology.Nodes[currentNodeId], currentPacket, $"to={nextNodeId}");
                return;
            }

            timeMs += LinkDelayMs();
            currentPacket = AdvancePathPacket(currentPacket, nextNode, hop);
            _metrics.RecordWinnerSelection(currentPacket with { MaliciousWinners = currentPacket.MaliciousWinners - (nextNode.IsMalicious ? 1 : 0) }, nextNode);
            _metrics.RecordTransmit(currentPacket);
            _metrics.RecordPacketArrival();
            _metrics.RecordEvent(timeMs, "PathRelayArrive", nextNode, currentPacket);
            currentNodeId = nextNodeId;
        }

        CompleteRendezvous(topology, timeMs, currentPacket, currentNodeId);
    }

    private void SimulateRandomWalk(Topology topology, double startTimeMs, Packet packet)
    {
        var currentNodeId = packet.SourceNodeId;
        var timeMs = startTimeMs;
        var currentPacket = packet;

        for (var hop = 1; hop <= Math.Max(1, _parameters.Ttl); hop++)
        {
            var neighbors = topology.Neighbors[currentNodeId];
            if (neighbors.Count == 0)
            {
                RecordAttackEstimate(currentPacket);
                _metrics.MarkFailed(currentPacket, "random_walk_dead_end");
                return;
            }

            var nextNodeId = neighbors[_random.NextInt(neighbors.Count)];
            var nextNode = topology.Nodes[nextNodeId];
            if (_random.Chance(_parameters.LossProbability))
            {
                RecordAttackEstimate(currentPacket);
                _metrics.MarkFailed(currentPacket, "walk_link_lost");
                _metrics.RecordEvent(timeMs, "PacketLost", topology.Nodes[currentNodeId], currentPacket, $"to={nextNodeId}");
                return;
            }

            timeMs += LinkDelayMs();
            currentPacket = AdvancePathPacket(currentPacket, nextNode, hop);
            _metrics.RecordWinnerSelection(currentPacket with { MaliciousWinners = currentPacket.MaliciousWinners - (nextNode.IsMalicious ? 1 : 0) }, nextNode);
            _metrics.RecordTransmit(currentPacket);
            _metrics.RecordPacketArrival();
            _metrics.RecordEvent(timeMs, "RandomWalkArrive", nextNode, currentPacket);
            currentNodeId = nextNodeId;
        }

        CompleteRendezvous(topology, timeMs, currentPacket, currentNodeId);
    }

    private void SimulateFlooding(Topology topology, double startTimeMs, Packet packet)
    {
        var seen = new HashSet<int>();
        var queue = new Queue<FloodVisit>();
        queue.Enqueue(new FloodVisit(packet.SourceNodeId, PreviousNodeId: -1, Depth: 0, ArrivalMs: startTimeMs));
        var maxArrivalMs = startTimeMs;

        while (queue.Count > 0)
        {
            var visit = queue.Dequeue();
            var node = topology.Nodes[visit.NodeId];
            _metrics.RecordPacketArrival();

            if (!seen.Add(visit.NodeId))
            {
                _metrics.RecordDuplicateDrop();
                continue;
            }

            node.BroadcastSeenCache.Add(packet.PacketId);
            maxArrivalMs = Math.Max(maxArrivalMs, visit.ArrivalMs);
            _metrics.RecordEvent(visit.ArrivalMs, "FloodArrive", node, packet with { HopIndex = visit.Depth });

            if (visit.Depth >= Math.Max(1, _parameters.Config.Shye.FloodDepth))
            {
                continue;
            }

            foreach (var neighborId in topology.Neighbors[visit.NodeId])
            {
                if (neighborId == visit.PreviousNodeId)
                {
                    continue;
                }

                if (_random.Chance(_parameters.LossProbability))
                {
                    _metrics.RecordEvent(visit.ArrivalMs, "PacketLost", node, packet, $"to={neighborId}");
                    continue;
                }

                var nextPacket = packet with { HopIndex = visit.Depth + 1 };
                _metrics.RecordTransmit(nextPacket);
                queue.Enqueue(new FloodVisit(
                    neighborId,
                    visit.NodeId,
                    visit.Depth + 1,
                    visit.ArrivalMs + LinkDelayMs()));
            }
        }

        var terminalNodeId = seen.Count == 0 ? packet.SourceNodeId : seen.OrderBy(id => StableDigest(packet.PacketId, id, _parameters.Seed)).First();
        CompleteRendezvous(topology, maxArrivalMs, packet with { HopIndex = Math.Max(1, _parameters.Config.Shye.FloodDepth) }, terminalNodeId);
    }

    private Packet AdvancePathPacket(Packet packet, Node nextNode, int hop)
    {
        return packet with
        {
            HopIndex = hop,
            RemainingTtl = Math.Max(0, packet.RemainingTtl - 1),
            MaliciousWinners = packet.MaliciousWinners + (nextNode.IsMalicious ? 1 : 0)
        };
    }

    private void CompleteRendezvous(Topology topology, double timeMs, Packet packet, int nodeId)
    {
        var success = CanRendezvousDeliver(topology, packet.AuctionId);
        _metrics.RecordRendezvousAttempt(success);
        if (success)
        {
            RecordAttackEstimate(packet);
            _metrics.MarkDelivered(packet, timeMs + _parameters.Config.CryptoCost.ThresholdDecryptMs, nodeId);
            _metrics.RecordEvent(timeMs, "RendezvousDelivered", topology.Nodes[nodeId], packet);
        }
        else
        {
            RecordAttackEstimate(packet);
            _metrics.MarkFailed(packet, "rendezvous_unavailable");
            _metrics.RecordEvent(timeMs, "RendezvousFailed", topology.Nodes[nodeId], packet);
        }
    }

    private bool CanRendezvousDeliver(Topology topology, string auctionId)
    {
        var f = Math.Max(0, _parameters.Config.Shye.RendezvousF);
        var n = Math.Min(topology.Nodes.Count, 3 * f + 1);
        if (n == 0) return false;

        var threshold = Math.Min(n, 2 * f + 1);
        var committee = topology.Nodes
            .OrderBy(node => StableDigest($"rv-{auctionId}", node.Id, _parameters.Seed))
            .Take(n);
        return committee.Count(node => !node.IsMalicious) >= threshold;
    }

    private void WriteStateSamples(Topology topology)
    {
        var interval = Math.Max(1.0, _parameters.Config.Traffic.StateSampleIntervalMs);
        var maxTime = _parameters.Config.Traffic.SimulationDurationMs + _parameters.Config.Traffic.MaxTailMs;
        for (var time = 0.0; time <= maxTime; time += interval)
        {
            _metrics.WriteNodeState(time, topology.Nodes);
        }
    }

    private int PickGlobalRelay(Topology topology, int currentNodeId)
    {
        if (topology.Nodes.Count <= 1) return currentNodeId;

        var next = _random.NextInt(topology.Nodes.Count - 1);
        return next >= currentNodeId ? next + 1 : next;
    }

    private int PickDifferentNode(int source)
    {
        if (_parameters.NodeCount <= 1) return source;

        var destination = _random.NextInt(_parameters.NodeCount - 1);
        return destination >= source ? destination + 1 : destination;
    }

    private double LinkDelayMs()
    {
        return _parameters.Config.Network.BaseDelayMs
            + _random.NextDouble() * _parameters.Config.Network.JitterMs;
    }

    private int BaselinePacketSize()
    {
        return _parameters.Config.Traffic.RealPacketBytes
            + _parameters.Config.CryptoCost.ForwarderSignatureBytes;
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

    #endregion
   
}

internal sealed record FloodVisit(int NodeId, int PreviousNodeId, int Depth, double ArrivalMs);
