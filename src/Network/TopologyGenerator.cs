using Shye.Core;

namespace Shye.Network;

/// <summary>
/// Generates overlay-network topologies for simulation runs.
/// </summary>
public static class TopologyGenerator
{
    public static Topology Generate(string name, int nodeCount, int averageDegree, double alpha, RandomSource random)
    {
        if (nodeCount <= 0) throw new ArgumentOutOfRangeException(nameof(nodeCount), "Node count must be positive.");
        var degree = Math.Clamp(averageDegree, 0, Math.Max(0, nodeCount - 1));

        var adjacency = Enumerable.Range(0, nodeCount).Select(_ => new HashSet<int>()).ToArray();
        switch (name.ToLowerInvariant())
        {
            case "regular_like":
            case "regular":
                BuildRegularLike(adjacency, degree, random);
                break;
            case "power_law":
            case "powerlaw":
                BuildPowerLaw(adjacency, degree, random);
                break;
            default:
                BuildRandom(adjacency, degree, random);
                break;
        }

        var nodes = Enumerable.Range(0, nodeCount)
            .Select(id => new Node(id, random.Chance(alpha)))
            .ToArray();

        return new Topology(nodes, adjacency.Select(set => (IReadOnlyList<int>)set.ToArray()).ToArray());
    }

    private static void BuildRandom(HashSet<int>[] adjacency, int degree, RandomSource random)
    {
        var n = adjacency.Length;
        if (n <= 1 || degree == 0) return;

        for (var i = 0; i < n; i++)
        {
            AddEdge(adjacency, i, (i + 1) % n);
        }

        var targetEdges = Math.Min(n * (n - 1) / 2, Math.Max(n, n * degree / 2));
        var attempts = 0;
        while (CountEdges(adjacency) < targetEdges && attempts < targetEdges * 100)
        {
            attempts++;
            var a = random.NextInt(n);
            var b = random.NextInt(n);
            AddEdge(adjacency, a, b);
        }
    }
    private static void BuildRegularLike(HashSet<int>[] adjacency, int degree, RandomSource random)
    {
        var n = adjacency.Length;
        if (n <= 1 || degree == 0) return;

        var half = Math.Max(1, degree / 2);
        for (var i = 0; i < n; i++)
        {
            for (var step = 1; step <= half; step++)
            {
                AddEdge(adjacency, i, (i + step) % n);
                AddEdge(adjacency, i, (i - step + n) % n);
            }
        }

        if (degree % 2 != 1 || n <= 2) return;
        {
            for (var i = 0; i < n; i++)
            {
                var target = random.NextInt(n);
                AddEdge(adjacency, i, target);
            }
        }
    }
    private static void BuildPowerLaw(HashSet<int>[] adjacency, int degree, RandomSource random)
    {
        var n = adjacency.Length;
        if (n <= 1 || degree == 0) return;

        var initial = Math.Min(n, Math.Max(3, degree));
        for (var i = 0; i < initial; i++)
        {
            for (var j = i + 1; j < initial; j++)
            {
                AddEdge(adjacency, i, j);
            }
        }

        var edgesPerNewNode = Math.Max(1, degree / 2);
        for (var node = initial; node < n; node++)
        {
            var chosen = new HashSet<int>();
            var guard = 0;
            while (chosen.Count < Math.Min(edgesPerNewNode, node) && guard < node * 20)
            {
                guard++;
                var target = PickPreferential(adjacency, node, random);
                if (target != node) chosen.Add(target);
            }

            foreach (var target in chosen)
            {
                AddEdge(adjacency, node, target);
            }
        }
    }

    private static int PickPreferential(HashSet<int>[] adjacency, int exclusiveUpperBound, RandomSource random)
    {
        var totalWeight = 0;
        for (var i = 0; i < exclusiveUpperBound; i++)
        {
            totalWeight += adjacency[i].Count + 1;
        }

        var pick = random.NextInt(totalWeight);
        var cumulative = 0;
        for (var i = 0; i < exclusiveUpperBound; i++)
        {
            cumulative += adjacency[i].Count + 1;
            if (pick < cumulative) return i;
        }

        return exclusiveUpperBound - 1;
    }
    private static void AddEdge(HashSet<int>[] adjacency, int a, int b)
    {
        if (a == b || a < 0 || b < 0 || a >= adjacency.Length || b >= adjacency.Length)
        {
            return;
        }

        adjacency[a].Add(b);
        adjacency[b].Add(a);
    }

    private static int CountEdges(HashSet<int>[] adjacency)
    {
        return adjacency.Sum(set => set.Count) / 2;
    }
}
