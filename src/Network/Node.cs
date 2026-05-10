namespace Shye.Network;

/// <summary>
/// Simulation node state used by topology, forwarding, and state-overhead metrics.
/// </summary>
public sealed class Node
{
    public Node(int id, bool isMalicious)
    {
        Id = id;
        IsMalicious = isMalicious;
    }

    public int Id { get; }
    public bool IsMalicious { get; }
    public HashSet<string> BroadcastSeenCache { get; } = new(StringComparer.Ordinal);
    public HashSet<string> ClaimTable { get; } = new(StringComparer.Ordinal);
}
