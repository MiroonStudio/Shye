using Shye.Protocols;

namespace Shye.Core;

public enum SimulationEventType
{
    MessageInject,
    CoverInject,
    ForwardStart,
    PacketArrive,
    AuctionSettle,
    RendezvousDeliver,
    StateSample
}

public sealed record SimulationEvent(
    double TimeMs,
    SimulationEventType Type,
    int NodeId = -1,
    int PreviousNodeId = -1,
    int DestinationNodeId = -1,
    Packet? Packet = null);
