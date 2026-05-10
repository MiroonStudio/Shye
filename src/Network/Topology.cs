namespace Shye.Network;

/// <summary>
/// Immutable overlay topology containing nodes and adjacency lists.
/// </summary>
public sealed class Topology
{
    public Topology(IReadOnlyList<Node> nodes, IReadOnlyList<int>[] neighbors)
    {
        Nodes = nodes;
        Neighbors = neighbors;
    }

    public IReadOnlyList<Node> Nodes { get; }
    public IReadOnlyList<int>[] Neighbors { get; }
}
