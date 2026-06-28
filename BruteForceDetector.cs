using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;

namespace ConsoleApp3
{

    internal class BruteForceDetector
    {

        // Tracks connection attempts per IP
        private readonly ConcurrentDictionary<string, IpConnectionProfile> ipProfiles = new();

        // hardcoding suspicious ports: SSH, RDP, Telnet
        private readonly HashSet<int> suspiciousPorts = [22, 23, 3389];

        // config values for brute-force detection
        public int ConnectionAttemptsThreshold { get; set; } = 10; // Default threshold for connection attempts
        public double TimeWindow { get; set; } = 60; // in seconds
        public int FailedConnectionsThreshold { get; set; } = 10; // number of failed connections to consider as brute-force
        public int PortSweepThreshold { get; set; } = 3; // number of different ports accessed by the same ip  

        // This event will be fired when a suspicious IP is detected
        public event EventHandler<BruteForceAlertEventArgs>? AttackDetected;

        public BruteForceDetector()
        {

        }

        /// <summary>
        /// main method of the dettector, should be called for each packet
        /// </summary>
        public void AnalyzePacket(Packet packet)
        {
            // packet could be null
            if (packet == null || !packet.IsTcp)
            {
                return;
            }

            // Only analyze packets to suspicious ports
            if (!packet.DestinationPort.HasValue || !suspiciousPorts.Contains(packet.DestinationPort.Value))
            {
                return;
            }

            var sourceIp = packet.SourceAddress;
            var destPort = packet.DestinationPort.Value;
            var destIp = packet.DestinationAddress;

            var profile = ipProfiles.GetOrAdd(sourceIp, _ => new IpConnectionProfile(sourceIp));

            // Track different types of connections
            if (packet.IsSyn && !packet.IsAcknowledgment)
            {
                // New connection attempt
                profile.RecordConnectionAttempt(destPort, packet.Timestamp);
                CheckForAttack(sourceIp, profile);
            }
            else if (packet.IsReset)
            {
                // Connection reset - could indicate failed login attempt
                profile.RecordFailedConnection(destPort, packet.Timestamp);
                CheckForAttack(sourceIp, profile);
            }
            else if (packet.IsAcknowledgment && !packet.IsSyn && packet.IsFin)
            {
                // Connection termination
                profile.RecordClosedConnection(destPort, packet.Timestamp);
            }
        }

        /// <summary>
        /// Checks if the IP profile indicates a brute-force attack
        /// </summary>
        private void CheckForAttack(string sourceIp, IpConnectionProfile profile)
        {
            var alerts = new List<string>();

            //  #1: Rapid connection attempts to same port
            foreach (var entry in profile.ConnectionAttemptsByPort)
            {
                var port = entry.Key;
                var attempts = entry.Value;

                // Get recent attempts (within time window)
                var recentAttempts = attempts
                    .Where(ts => (ts.CurrentTime - DateTime.Now).TotalSeconds < TimeWindow)
                    .ToList();

                if (recentAttempts.Count >= ConnectionAttemptsThreshold)
                {
                    alerts.Add($"High frequency connection attempts to port {port}: " +
                        $"{recentAttempts.Count} attempts in {TimeWindow} seconds");
                }
            }

            // #2: Multiple failed connections
            if (profile.FailedConnections >= FailedConnectionsThreshold)
            {
                alerts.Add($"Multiple failed connection attempts: {profile.FailedConnections} failures");
            }

            // #3: Scanning multiple ports (port sweep)
            var portsTargeted = profile.ConnectionAttemptsByPort.Keys.Count;
            if (portsTargeted >= PortSweepThreshold)
            {
                alerts.Add($"Port sweep detected: {portsTargeted} different ports targeted");
            }


            // Raise alert if any conditions are met
            if (alerts.Count > 0)
            {
                RaiseAlert(sourceIp, profile, alerts);
            }
        }

        /// <summary>
        /// Raises a brute-force attack alert
        /// </summary>
        private void RaiseAlert(string sourceIp, IpConnectionProfile profile, List<string> reasons)
        {
            var alert = new BruteForceAlertEventArgs
            {
                SourceIp = sourceIp,
                DetectedTime = DateTime.Now,
                TotalConnectionAttempts = profile.ConnectionAttempts,
                FailedConnections = profile.FailedConnections,
                TargetedPorts = [.. profile.ConnectionAttemptsByPort.Keys],
                Reasons = reasons,
                SuspicionLevel = CalculateSuspicionLevel(profile)
            };

            AttackDetected?.Invoke(this, alert);
        }

        private string CalculateSuspicionLevel(IpConnectionProfile profile)
        {
            var suspicionScore = 0;

            // For now I am giving all brute force vectors same weight. Can change later if needed
            
            // Score based on connection attempts
            if(profile.ConnectionAttempts > ConnectionAttemptsThreshold)
            {
                suspicionScore += 15 * (profile.ConnectionAttempts / ConnectionAttemptsThreshold);
            }

            // Score based on failed connections
            if (profile.FailedConnections > FailedConnectionsThreshold)
            {
                suspicionScore += 15 * (profile.FailedConnections / FailedConnectionsThreshold);
            }

            // Score based on port scanning
            if (profile.ConnectionAttemptsByPort.Count > PortSweepThreshold)
            {
                suspicionScore += 15 * (profile.ConnectionAttemptsByPort.Count / PortSweepThreshold);
            }

            var suspicionLevel = "";

            if (suspicionScore >= 95)
                suspicionLevel = "CRITICAL";
            else if (suspicionScore >= 60)
                suspicionLevel = "HIGH";
            else if (suspicionScore >= 30)
                suspicionLevel = "MEDIUM";
            else
            {
                suspicionLevel = "LOW";
            }


            return suspicionLevel;
        }

        /// <summary>
        /// Gets the profile for a specific IP
        /// </summary>
        public IpConnectionProfile? GetProfile(string sourceIp)
        {
            ipProfiles.TryGetValue(sourceIp, out var profile);
            return profile;
        }

        /// <summary>
        /// Get rofiles for all suspicious IPs
        /// </summary>
        public List<IpConnectionProfile> GetSuspiciousProfiles()
        {
            return [.. ipProfiles.Values
                .Where(p => p.ConnectionAttempts > ConnectionAttemptsThreshold ||
                           p.FailedConnections > FailedConnectionsThreshold ||
                           p.ConnectionAttemptsByPort.Count > PortSweepThreshold)];
        }

        /// <summary>
        /// Clears old profiles to free memory
        /// </summary>
        public void CleanupOldProfiles(double maxTimeout = 3600)
        {
            var now = DateTime.Now;
            var keysToRemove = (List<string>)[.. ipProfiles
                .Where(kvp => (now - kvp.Value.LastActivityTime).TotalSeconds > maxTimeout)
                .Select(kvp => kvp.Key)];

            foreach (var key in keysToRemove)
            {
                ipProfiles.TryRemove(key, out _);
            }
        }
    }

    /// <summary>
    /// Tracks connection information for a specific source IP
    /// </summary>
    public class IpConnectionProfile(string sourceIp)
    {
        public string SourceIp { get; set; } = sourceIp;
        public int ConnectionAttempts { get; set; }
        public int FailedConnections { get; set; }
        public DateTime LastActivityTime { get; set; } = DateTime.Now;

        public Dictionary<int, List<TimestampRecord>> ConnectionAttemptsByPort { get; set; } = [];

        public void RecordConnectionAttempt(int destPort, double timestamp)
        {
            ConnectionAttempts++;
            LastActivityTime = DateTime.Now;

            // Track by port
            if (!ConnectionAttemptsByPort.ContainsKey(destPort))
            {
                ConnectionAttemptsByPort[destPort] = [];
            }

            ConnectionAttemptsByPort[destPort].Add(new TimestampRecord { Timestamp = timestamp, CurrentTime = DateTime.Now });
        }

        public void RecordFailedConnection(int destPort, double timestamp)
        {
            FailedConnections++;
            LastActivityTime = DateTime.Now;
        }

        public void RecordClosedConnection(int destPort, double timestamp)
        {
            LastActivityTime = DateTime.Now;
        }

        public override string ToString()
        {
            return $"IP: {SourceIp} | Attempts: {ConnectionAttempts} | Failed: {FailedConnections} | " +
                   $"Ports: {ConnectionAttemptsByPort.Count}";
        }
    }

    /// <summary>
    /// Records a timestamp with capture context
    /// </summary>
    public class TimestampRecord
    {
        public double Timestamp { get; set; }
        public DateTime CurrentTime { get; set; }
    }

    /// <summary>
    /// Event arguments for brute-force attack detection
    /// </summary>
    public class BruteForceAlertEventArgs : EventArgs
    {
        public string SourceIp { get; set; }
        public DateTime DetectedTime { get; set; }
        public int TotalConnectionAttempts { get; set; }
        public int FailedConnections { get; set; }
        public List<int> TargetedPorts { get; set; } = [];
        public List<string> TargetedIps { get; set; } = [];
        public List<string> Reasons { get; set; } = [];
        public string SuspicionLevel { get; set; }

        public override string ToString()
        {
            return $@"
╔═══════════════════════════════════════════════════════════════╗
║          ⚠️  BRUTE-FORCE ATTACK DETECTED  ⚠️                 ║
╚═══════════════════════════════════════════════════════════════╝
[{SuspicionLevel}] Source IP: {SourceIp}
Detected: {DetectedTime:yyyy-MM-dd HH:mm:ss}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Connection Stats:
   Total Attempts: {TotalConnectionAttempts}
   Failed Connections: {FailedConnections}
   Targeted Ports: {string.Join(", ", TargetedPorts)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Alert Reasons:
{string.Join(Environment.NewLine, Reasons.Select(r => "   • " + r))}
╔═══════════════════════════════════════════════════════════════╗
";
        }
    }
}
