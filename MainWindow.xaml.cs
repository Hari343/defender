using ConsoleApp3;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Path = System.IO.Path;

namespace WpfApp2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // Cancellation token to signal threads to stop
        private static CancellationTokenSource cancellationTokenSource = new();
        private static readonly BruteForceDetector bruteForceDetector = new();

        // tshark
        private TsharkInterface? tsharkInterface;
        private bool isCapturing = false;

        
        // log file related items
        private string logFile;
        private Lock logFileLock = new();
        private StringBuilder logFileBuffer = new();

        private HashSet<string> blockedIps = [];

        private readonly Dictionary<int, string> protocolPortMap = new()
        {
            {3389, "RDP" },
            {22, "SSH" },
            {23, "Telnet"},
            {80, "HTTP" },
            {443, "HTTPS" }
        };
        public MainWindow()
        {
            InitializeComponent();

            // Subscribe to attack detection events
            bruteForceDetector.AttackDetected += OnBruteForceAttackDetected;
        }

        

        // load all network interfaces
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            cmbNetworkInterface.Items.Clear();
            foreach (var item in TsharkInterface.GetAvailableInterfaces())
            {
                cmbNetworkInterface.Items.Add(item.Name);
            }
        }

        void ProcessAndAnalyzePackets(ConcurrentQueue<Packet> packetQueue, CancellationToken cancellationToken)
        {
            try
            {
                var packetCount = 0;
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (packetQueue.TryDequeue(out Packet? packet))
                    {
                        if (packet != null)
                        {
                            packetCount++;
                            // Analyze packet for brute-force indicators
                            bruteForceDetector.AnalyzePacket(packet);

                            // Display packet
                            var protocol = "~";
                            if (packet.DestinationPort != null && protocolPortMap.TryGetValue((int)packet.DestinationPort, out var value))
                            {
                                protocol = value;
                            }
                            Log($"[{packetCount}] Protocol: [{protocol}] Src: {packet.SourceAddress}:{packet.SourcePort} -> Dst: {packet.DestinationAddress}:{packet.DestinationPort}");
                        }
                    }
                    else
                    {
                        Thread.Sleep(100);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] {ex.Message}");
            }
        }

        // This is the output of the process' standard error stream. Not necessarily needs to be a real error.
        void DisplayErrors(ConcurrentQueue<string> errorQueue, CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (errorQueue.TryDequeue(out string? error))
                    {
                        if (!string.IsNullOrEmpty(error))
                        {
                            Log($"{error}");
                        }
                    }
                    else
                    {
                        Thread.Sleep(100);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DisplayErrors Error] {ex.Message}");
            }
        }

        void DisplaySuspiciousIps(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    Thread.Sleep(10000); // Update every 10 seconds

                    if (!cancellationToken.IsCancellationRequested)
                    {
                        var suspicious = bruteForceDetector.GetSuspiciousProfiles();
                        if (suspicious.Count > 0)
                        {
                            Log($"\n[INFO] Suspicious IPs: {suspicious.Count}");
                            foreach (var profile in suspicious.Take(5)) // Lets only show Top 5
                            {
                                Log($"  -> {profile}");
                            }
                        }

                        // Cleanup old profiles every 10 seconds
                        bruteForceDetector.CleanupOldProfiles(300);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[DisplaySuspiciousIps Error] {ex.Message}");
            }
        }

        void DisplayFinalSuspiciousReport()
        {
            var suspicious = bruteForceDetector.GetSuspiciousProfiles();
            if (suspicious.Count > 0)
            {
                Log("\n╔════════════════════════════════════════╗");
                Log("║   FINAL SUSPICIOUS IPs REPORT          ║");
                Log("╚════════════════════════════════════════╝");
                foreach (var profile in suspicious.OrderByDescending(p => p.ConnectionAttempts))
                {
                    Log($"  {profile}");
                }
            }
        }

        void OnBruteForceAttackDetected(object? sender, BruteForceAlertEventArgs e)
        {
            // This suspicionLevel color thingy is not very useful currently. For line specific coloring in the GUI, we need to use a RichTextBox. Will come back to this if I have time. For now this is just a placeholder.   
            if (e.SuspicionLevel == "CRITICAL")
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            else if (e.SuspicionLevel == "HIGH")
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
            }
            else if (e.SuspicionLevel == "MEDIUM")
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.White;
            }

            // Block the IP if the suspicion level reaches CRITICAL - Needs admin privileges
            var maliciousIp = e.SourceIp;
            if (e.SuspicionLevel == "CRITICAL" && !blockedIps.Contains(maliciousIp))
            {
                var status = BlacklistIpUsingPowerShell(maliciousIp);
                if (status)
                {
                    blockedIps.Add(maliciousIp);
                    Log($"Successfully blocked IP {maliciousIp}");
                }
                else
                {
                    Log($"Unable to block IP {maliciousIp}. Are you running Defender with admin priviliges?");
                }

            }


            Log(e.ToString());
        }

        private bool BlacklistIpUsingPowerShell(string maliciousIp)
        {
            var ruleName = "Adamantine Shield";
            var arguments = $"-NoProfile -WindowStyle Hidden -Command \"New-NetFirewallRule -DisplayName '{ruleName}' -Direction Inbound -Action Block -RemoteAddress '{maliciousIp}'\"";

            var processStartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = arguments,
                Verb = "runas", // requesting elevated PowerShell access
                UseShellExecute = true,
                CreateNoWindow = true
            };

            try
            {
                using Process process = Process.Start(processStartInfo)!;
                process.WaitForExit();
                if (process.ExitCode == 0)
                {
                    return true;
                }
                else
                    Log($"PowerShell failed with exit code: {process.ExitCode}");
                return false;
            }
            catch (Exception e) 
            {
                Log("Unable to block IP using PowerShell: " + e.Message);
                return false;
            }
        }

        // Will both log on-screen and on file
        private void Log(string message)
        {
            
            logText.Dispatcher.BeginInvoke(new Action(() =>
            {
                logText.AppendText(message + "\n");
                logText.ScrollToEnd();
            }));

            // log to file
            if (!string.IsNullOrEmpty(logFile))
            {
                lock (logFileLock)
                {
                    var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message} \n";
                    logFileBuffer.Append(entry);
                }
            }
        }

        private bool VerifyInputs(string tsharkLocation, string logFileLocation, string pcapFileLocation)
        {
            // Check for tshark
            if (!File.Exists(tsharkLocation))
            {
                Log("tshark.exe not found in the Wireshark location. Please check the path.");
                return false;
            }

            // Check for log file location
            if (!string.IsNullOrEmpty(logFileLocation) && !Directory.Exists(Path.GetDirectoryName(logFileLocation)))
            {
                Log("Log file location does not exist. Please check the path.");
                return false;
            }

            // Check for pcap file location
            if (!string.IsNullOrEmpty(pcapFileLocation) && !Directory.Exists(Path.GetDirectoryName(pcapFileLocation)))
            {
                Log("PCAP file location does not exist. Please check the path.");
                return  false;
            }

         
            return true;
        }

        private void Start_Wireshark(object sender, RoutedEventArgs e)
        {
            var wiresharkLocation = txtWireSharkLocation.Text + @"\wireshark.exe";
            if (File.Exists(wiresharkLocation))
            {
                Process.Start(wiresharkLocation);
            } else
            {
                Log("Wireshark not found. Please check path");
            }
        }

        private void StartCapture()
        {
            var selectedInterface = (cmbNetworkInterface.SelectedItem.ToString() ?? "Wi-Fi").Trim();

            var tsharkLocation = txtWireSharkLocation.Text.Trim() + @"\tshark.exe";
            var logFileLocation = txtLogLocation.Text.Trim();
            var pcapFileLocation = txtPcapLocation.Text.Trim();


            // Check inputs
            if (!VerifyInputs(tsharkLocation, logFileLocation, pcapFileLocation))
            {
                return;
            }

            // initialize log file - it can be null
            logFile = logFileLocation;


            // Retrieve selected protocols
            var protocolPorts = (List<int>)[];
            if(chkRDP.IsChecked == true)
            {
                protocolPorts.Add(3389); // RDP port
            }

            if (chkSSH.IsChecked == true)
            {
                protocolPorts.Add(22); // SSH port
            }

            if (chkTelnet.IsChecked == true)
            {
                protocolPorts.Add(23); // Telnet port
            }

            btnStart.Content = "Stop Capture";
            isCapturing = true;

            // reset Log file buffer
            logFileBuffer.Clear();

            // reinitialize cancellation token source
            cancellationTokenSource.Dispose();
            cancellationTokenSource = new CancellationTokenSource();

            var packetQueue = new ConcurrentQueue<Packet>();
            var errorQueue = new ConcurrentQueue<string>();

            try
            {

                tsharkInterface = new TsharkInterface(packetQueue, errorQueue, tsharkLocation, pcapFileLocation);

                Log($"\nStarting capture on interface: {selectedInterface}");
                tsharkInterface.StartCapture(selectedInterface, protocolPorts: protocolPorts.Count > 0 ? protocolPorts : null);

                // Start display threads
                var thread1 = new Thread(() => ProcessAndAnalyzePackets(packetQueue, cancellationTokenSource.Token));
                var thread2 = new Thread(() => DisplayErrors(errorQueue, cancellationTokenSource.Token));
                var thread3 = new Thread(() => DisplaySuspiciousIps(cancellationTokenSource.Token));

                thread1.Start();
                thread2.Start();
                thread3.Start();

                Log("\nCapture running...");
            }
            catch (Exception e) {
                Log("[ERROR] Unable to Start Capture");
                Log("[ERROR] " + e.Message);
            }

        }

        private void StopCapture()
        {
            cancellationTokenSource.Cancel(); // this will stop all the threads
            tsharkInterface?.StopCapture();
            isCapturing = false;
            btnStart.Content = "Start";
            Log("Capture stopped successfully");

            // write the log file buffer contents to file
            if (!string.IsNullOrEmpty(logFile))
            {
                lock (logFileLock)
                {
                    File.AppendAllText(logFile, logFileBuffer.ToString());
                }
            }

        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (!isCapturing)
            {
                StartCapture();
            } else
            {
                StopCapture();
            }
        }

        private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            this.DragMove();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}