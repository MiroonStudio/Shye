using System.Globalization;
using System.Text;
using Shye.Configuration;

namespace Shye.Metrics;

public sealed class CsvOutput : IAsyncDisposable
{
    #region Private Fields

    private readonly StreamWriter? _events;
    private readonly StreamWriter _messages;
    private readonly StreamWriter? _nodeState;
    private readonly StreamWriter _runMetrics;

    #endregion

    #region Public Methods

    public CsvOutput(string directory, OutputConfig config)
    {
        Directory.CreateDirectory(directory);

        if (config.WriteEvents)
        {
            _events = CreateWriter(Path.Combine(directory, "events.csv"));
            _events.WriteLine("run_id,seed,time_ms,event_type,node_id,message_id,packet_id,hop_index,auction_id,bytes,is_cover,is_malicious,detail");
        }

        _messages = CreateWriter(Path.Combine(directory, "messages.csv"));
        _messages.WriteLine("run_id,seed,message_id,source_id,destination_id,protocol,topology,N,d,ttl,alpha,injected_at_ms,delivered_at_ms,success,fail_reason,hop_count,total_broadcasts,total_bytes,malicious_winners,source_identified,path_linked");

        if (config.WriteNodeState)
        {
            _nodeState = CreateWriter(Path.Combine(directory, "node_state.csv"));
            _nodeState.WriteLine("run_id,seed,time_ms,node_id,is_malicious,broadcast_seen_cache_size,claim_table_size,witness_queue_size,rendezvous_queue_size,expired_state_count");
        }

        _runMetrics = CreateWriter(Path.Combine(directory, "run_metrics.csv"));
        _runMetrics.WriteLine("run_id,seed,experiment,variant,protocol,topology,N,d,ttl,tau_settle,lambda_cover,lambda_msg,alpha,p_loss,observer_mode,identity_multiplier,grinding_attempts,disable_commit_reveal,disable_link_proof,disable_rerandomization,enable_stable_route_tag,delivery_success_rate,latency_avg_ms,latency_p50_ms,latency_p95_ms,throughput_msg_per_sec,total_broadcasts,total_bytes,duplicate_drop_ratio,source_identification_success_rate,path_linking_success_rate,path_capture_probability,malicious_winner_ratio,winner_cert_success_rate,settlement_timeout_ratio,rendezvous_delivery_success_rate");
    }

    public void WriteEvent(EventRecord record)
    {
        _events?.WriteLine(string.Join(',',
            E(record.RunId),
            record.Seed,
            F(record.TimeMs),
            record.EventType,
            record.NodeId,
            E(record.MessageId),
            E(record.PacketId),
            record.HopIndex,
            E(record.AuctionId),
            record.Bytes,
            B(record.IsCover),
            B(record.IsMalicious),
            E(record.Detail)));
    }

    public void WriteMessage(MessageOutput record)
    {
        _messages.WriteLine(string.Join(',',
            E(record.RunId),
            record.Seed,
            E(record.MessageId),
            record.SourceId,
            record.DestinationId,
            E(record.Protocol),
            E(record.Topology),
            record.NodeCount,
            record.AverageDegree,
            record.Ttl,
            F(record.Alpha),
            F(record.InjectedAtMs),
            record.DeliveredAtMs.HasValue ? F(record.DeliveredAtMs.Value) : "",
            B(record.Success),
            E(record.FailReason),
            record.HopCount,
            record.TotalBroadcasts,
            record.TotalBytes,
            record.MaliciousWinners,
            B(record.SourceIdentified),
            B(record.PathLinked)));
    }

    public void WriteNodeState(NodeStateOutput record)
    {
        _nodeState?.WriteLine(string.Join(',',
            E(record.RunId),
            record.Seed,
            F(record.TimeMs),
            record.NodeId,
            B(record.IsMalicious),
            record.BroadcastSeenCacheSize,
            record.ClaimTableSize,
            record.WitnessQueueSize,
            record.RendezvousQueueSize,
            record.ExpiredStateCount));
    }

    public void WriteRunMetrics(RunMetricsOutput record)
    {
        _runMetrics.WriteLine(string.Join(',',
            E(record.RunId),
            record.Seed,
            E(record.Experiment),
            E(record.Variant),
            E(record.Protocol),
            E(record.Topology),
            record.NodeCount,
            record.AverageDegree,
            record.Ttl,
            F(record.TauSettle),
            F(record.LambdaCover),
            F(record.LambdaMsg),
            F(record.Alpha),
            F(record.LossProbability),
            E(record.ObserverMode),
            F(record.IdentityMultiplier),
            record.GrindingAttempts,
            B(record.DisableCommitReveal),
            B(record.DisableLinkProof),
            B(record.DisableRerandomization),
            B(record.EnableStableRouteTag),
            F(record.DeliverySuccessRate),
            F(record.LatencyAvgMs),
            F(record.LatencyP50Ms),
            F(record.LatencyP95Ms),
            F(record.ThroughputMsgPerSec),
            record.TotalBroadcasts,
            record.TotalBytes,
            F(record.DuplicateDropRatio),
            F(record.SourceIdentificationSuccessRate),
            F(record.PathLinkingSuccessRate),
            F(record.PathCaptureProbability),
            F(record.MaliciousWinnerRatio),
            F(record.WinnerCertSuccessRate),
            F(record.SettlementTimeoutRatio),
            F(record.RendezvousDeliverySuccessRate)));
    }

    public async Task FlushAsync()
    {
        if (_events is not null) await _events.FlushAsync();
        await _messages.FlushAsync();
        if (_nodeState is not null) await _nodeState.FlushAsync();
        await _runMetrics.FlushAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_events is not null) await _events.DisposeAsync();
        await _messages.DisposeAsync();
        if (_nodeState is not null) await _nodeState.DisposeAsync();
        await _runMetrics.DisposeAsync();
    }

    #endregion

    #region Private Methods

    private static StreamWriter CreateWriter(string path)
    {
        return new StreamWriter(path, append: false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static string F(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value)) return "";
        return value.ToString("0.######", CultureInfo.InvariantCulture);
    }

    private static string B(bool value) => value ? "true" : "false";

    private static string E(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (!value.Contains(',') && !value.Contains('"') && !value.Contains('\n') && !value.Contains('\r'))
        {
            return value;
        }

        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    #endregion
}

public sealed record EventRecord(
    string RunId,
    int Seed,
    double TimeMs,
    string EventType,
    int NodeId,
    string? MessageId,
    string? PacketId,
    int HopIndex,
    string? AuctionId,
    int Bytes,
    bool IsCover,
    bool IsMalicious,
    string? Detail);

public sealed record MessageOutput(
    string RunId,
    int Seed,
    string MessageId,
    int SourceId,
    int DestinationId,
    string Protocol,
    string Topology,
    int NodeCount,
    int AverageDegree,
    int Ttl,
    double Alpha,
    double InjectedAtMs,
    double? DeliveredAtMs,
    bool Success,
    string FailReason,
    int HopCount,
    long TotalBroadcasts,
    long TotalBytes,
    int MaliciousWinners,
    bool SourceIdentified,
    bool PathLinked);

public sealed record NodeStateOutput(
    string RunId,
    int Seed,
    double TimeMs,
    int NodeId,
    bool IsMalicious,
    int BroadcastSeenCacheSize,
    int ClaimTableSize,
    int WitnessQueueSize,
    int RendezvousQueueSize,
    int ExpiredStateCount);

public sealed record RunMetricsOutput(
    string RunId,
    int Seed,
    string Experiment,
    string Variant,
    string Protocol,
    string Topology,
    int NodeCount,
    int AverageDegree,
    int Ttl,
    double TauSettle,
    double LambdaCover,
    double LambdaMsg,
    double Alpha,
    double LossProbability,
    string ObserverMode,
    double IdentityMultiplier,
    int GrindingAttempts,
    bool DisableCommitReveal,
    bool DisableLinkProof,
    bool DisableRerandomization,
    bool EnableStableRouteTag,
    double DeliverySuccessRate,
    double LatencyAvgMs,
    double LatencyP50Ms,
    double LatencyP95Ms,
    double ThroughputMsgPerSec,
    long TotalBroadcasts,
    long TotalBytes,
    double DuplicateDropRatio,
    double SourceIdentificationSuccessRate,
    double PathLinkingSuccessRate,
    double PathCaptureProbability,
    double MaliciousWinnerRatio,
    double WinnerCertSuccessRate,
    double SettlementTimeoutRatio,
    double RendezvousDeliverySuccessRate);
