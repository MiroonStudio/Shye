namespace Shye.Core;

public sealed class EventQueue
{
    #region Private Fields

    private readonly PriorityQueue<SimulationEvent, EventPriority> _queue = new();
    
    private long _sequence;
    
    #endregion

    #region Public Field

    public int Count => _queue.Count;

    #endregion

    #region Pubilc Methods

    public void Enqueue(SimulationEvent simulationEvent)
    {
        _queue.Enqueue(simulationEvent, new EventPriority(simulationEvent.TimeMs, _sequence++));
    }

    public bool TryDequeue(out SimulationEvent simulationEvent) => _queue.TryDequeue(out simulationEvent!, out _);

    #endregion
}

internal readonly record struct EventPriority(double TimeMs, long Sequence) : IComparable<EventPriority>
{
    #region Public Method

    public int CompareTo(EventPriority other)
    {
        var timeCompare = TimeMs.CompareTo(other.TimeMs);
        return timeCompare != 0 ? timeCompare : Sequence.CompareTo(other.Sequence);
    }

    #endregion
}
