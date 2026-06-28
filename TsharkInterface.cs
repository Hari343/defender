using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;

namespace WpfApp2
{
    internal class TsharkInterface(ConcurrentQueue<Packet> packetQueue, ConcurrentQueue<string> errorQueue, string tsharkPath, string captureFilePath)
    {

        private string tsharkPath = tsharkPath;
        private string captureFilePath = captureFilePath;

        private Process? captureProcess;
        private bool isCapturing = false;

        private readonly ConcurrentQueue<Packet> packetQueue = packetQueue;
        private readonly ConcurrentQueue<string> errorQueue = errorQueue;

        /// <summary>
        /// Validates that TShark is installed and accessible
        /// </summary>
        public bool ValidateTsharkInstallation()
        {
            return File.Exists(tsharkPath);

        }

        /// <summary>
        /// Gets a list of available network interfaces
        /// </summary>
        /// <returns>Dictionary with interface index and details (name, description, status)</returns>
        public static List<NetworkInterfaceInfo> GetAvailableInterfaces()
        {
            var interfaces = (List<NetworkInterfaceInfo>)[];

            try
            {
                var nics = NetworkInterface.GetAllNetworkInterfaces();

                foreach (var nic in nics)
                {
                    // Filter only interfaces that are up and connected
                    if (nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        nic.OperationalStatus == OperationalStatus.Up)
                    {
                        interfaces.Add(new NetworkInterfaceInfo
                        {
                            Name = nic.Name,
                            Description = nic.Description,
                            Status = nic.OperationalStatus.ToString(),
                            MacAddress = nic.GetPhysicalAddress().ToString()
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error retrieving network interfaces: " + ex.Message, ex);
            }

            if (interfaces.Count == 0)
            {
                throw new Exception("No active network interfaces found.");
            }

            return interfaces;
        }

        /// <summary>
        /// Displays available network interfaces. Not used in GUI app.
        /// </summary>
        public void DisplayAvailableInterfaces()
        {
            try
            {
                var interfaces = GetAvailableInterfaces();

                Console.WriteLine("\n========== Available Network Interfaces ==========");
                foreach (var netInterface in interfaces)
                {
                    Console.WriteLine($"\n{netInterface.Name}");
                    Console.WriteLine($"    Description: {netInterface.Description}");
                    Console.WriteLine($"    Status: {netInterface.Status}");
                    Console.WriteLine($"    MAC Address: {netInterface.MacAddress}");
                }
                Console.WriteLine("\n===================================================\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error displaying interfaces: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the TShark interface name for a given network interface
        /// </summary>
        /// <param name="dotnetInterfaceName">Network interface name from .NET API</param>
        /// <returns>TShark interface name</returns>
        private string GetTsharkInterfaceName(string dotnetInterfaceName)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = tsharkPath,
                        Arguments = "-D",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Parse TShark output to find matching interface
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains(dotnetInterfaceName))
                    {
                        // Extract interface number/name from TShark output
                        var match = Regex.Match(line, @"(\d+)\.\s+(.+?)\s+");
                        if (match.Success)
                        {
                            return match.Groups[1].Value;
                        }
                    }
                }

                return dotnetInterfaceName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not get TShark interface name: {ex.Message}");
                return dotnetInterfaceName;
            }
        }

        /// <summary>
        /// Starts capturing TCP packets from a selected interface
        /// </summary>
        /// <param name="interfaceName">Network interface name to capture from</param>
        /// <param name="ipAddr">Optional: IP address to filter (null for all)</param>
        /// <param name="protocolPorts">Optional: List of ports to filter (null for all)</param>
        /// <param name="writePcap">Whether to write the capture to a pcap file</param>
        public void StartCapture(string interfaceName, string? ipAddr = null, List<int>? protocolPorts = null, bool writePcap = false)
        {
            if (isCapturing)
            {
                Console.WriteLine("Capture is already running. Stop it first.");
                return;
            }

            try
            {
                if (string.IsNullOrEmpty(interfaceName))
                {
                    throw new ArgumentException("Interface name cannot be null or empty.");
                }

                // Build TShark capture filter (libpcap syntax)
                var filter = "tcp";

                if (!string.IsNullOrEmpty(ipAddr))
                {
                    filter += $" and host {ipAddr}";
                }

                if (protocolPorts != null && protocolPorts.Count > 0)
                {
                    var portFilter = string.Join(" or ", protocolPorts.Select(p => $"port {p}"));
                    filter += $" and ({portFilter})";
                }

                // Get TShark interface name
                var tsharkInterface = GetTsharkInterfaceName(interfaceName);

                // Build TShark command arguments
                var args = new StringBuilder();
                args.Append($"-i {tsharkInterface} ");
                args.Append($"-f \"{filter}\" "); // Capture filter using libpcap syntax
                args.Append("-l ");
                //args.Append("-P "); // Print in packet summary format
                args.Append("-T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.seq -e tcp.ack -e tcp.window_size -e tcp.len -E separator=/t");

                if (writePcap)
                {
                    // Ensure directory exists
                    var directory = Path.GetDirectoryName(captureFilePath);
                    if (!Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }
                    args.Append($" -w \"{captureFilePath}\" ");
                }

                captureProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = tsharkPath,
                        Arguments = args.ToString(),
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                captureProcess.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        var packet = PacketParser.ParsePacket(e.Data);
                        if (packet != null)
                        {
                            packetQueue.Enqueue(packet);
                        }
                    }
                };

                captureProcess.ErrorDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        errorQueue.Enqueue(e.Data);
                    }
                };

                captureProcess.Start();
                captureProcess.BeginOutputReadLine();
                captureProcess.BeginErrorReadLine();

                isCapturing = true;
                Console.WriteLine($"\nCapture started on interface: {interfaceName}");
                Console.WriteLine($"Capture filter: {filter}");
                if (writePcap)
                {
                    Console.WriteLine($"Saving pcap file to: {captureFilePath}");
                }
                Console.WriteLine("Waiting for packets...\n");
            }
            catch (Exception ex)
            {
                isCapturing = false;
                throw new Exception($"Error starting capture: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Stops the currently running TCP packet capture
        /// </summary>
        public void StopCapture()
        {
            if (!isCapturing || captureProcess == null)
            {
                Console.WriteLine("No capture is currently running.");
                return;
            }

            try
            {
                if (!captureProcess.HasExited)
                {
                    captureProcess.Kill();
                    captureProcess.WaitForExit(5000);
                }

                isCapturing = false;
                Console.WriteLine("\nCapture stopped successfully.");

                //if (File.Exists(captureFilePath))
                //{
                //    FileInfo fileInfo = new FileInfo(captureFilePath);
                //    Console.WriteLine($"apture file size: {fileInfo.Length / 1024.0:F2} KB");
                //}
            }
            catch (Exception ex)
            {
                isCapturing = false;
                throw new Exception($"Error stopping capture: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Gets the current capture status
        /// </summary>
        public bool IsCapturing
        {
            get { return isCapturing && (captureProcess != null && !captureProcess.HasExited); }
        }
    }


    // Helper class to encapsulate Network Interface details
    public class NetworkInterfaceInfo
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Status { get; set; }
        public string MacAddress { get; set; }

        public override string ToString()
        {
            return $"{Name} - {Description} ({Status})";
        }
    }
}
