namespace Shye.Core;

/// <summary>
/// Seeded random-number helper used to keep simulation runs reproducible.
/// </summary>
public sealed class RandomSource
{
    #region Private Field

    /// <summary>
    /// Random time! :)
    /// </summary>
    private readonly Random _random;

    #endregion

    #region Public Methods

    public RandomSource(int seed)
    {
        _random = new Random(seed);
    }

    public int NextInt(int maxExclusive) => _random.Next(maxExclusive);

    public int NextInt(int minInclusive, int maxExclusive) => _random.Next(minInclusive, maxExclusive);

    public double NextDouble() => _random.NextDouble();

    public double NextExponentialSeconds(double ratePerSecond)
    {
        if (ratePerSecond <= 0.0)
        {
            return double.PositiveInfinity;
        }

        var u = Math.Max(1e-12, _random.NextDouble());
        return -Math.Log(u) / ratePerSecond;
    }

    public bool Chance(double probability)
    {
        return probability switch
        {
            <= 0.0 => false,
            >= 1.0 => true,
            _ => _random.NextDouble() < probability
        };
    }

    public int StableFork(string label)
    {
        unchecked
        {
            var hash = 17;
            var index = 0;
            for (; index < label.Length; index++)
            {
                var ch = label[index];
                hash = hash * 31 + ch;
            }
            return _random.Next() ^ hash;
        }
    }

    #endregion
}
