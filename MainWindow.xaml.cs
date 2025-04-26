using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using MahApps.Metro.Controls;
using System.Collections.ObjectModel;
using System.Windows.Controls;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Data;
using System.Windows.Controls.Primitives;
using System.Reflection;

namespace WpfApp1
{
    // NetworkDevice for UI representation
    public class NetworkDevice
    {
        public string IpAddress { get; set; }
        public string MacAddress { get; set; }
        public string Hostname { get; set; }
        public string Vendor { get; set; }
        public string OperatingSystem { get; set; }
        public string DeviceType { get; set; }
        public bool IsExpanded { get; set; } = false;

        public override string ToString()
        {
            return $"{IpAddress} | {MacAddress} | {(string.IsNullOrEmpty(Hostname) ? "N/A" : Hostname)} | " +
                   $"{Vendor} | {(string.IsNullOrEmpty(OperatingSystem) ? "Unknown" : OperatingSystem)} | " +
                   $"{(string.IsNullOrEmpty(DeviceType) ? "Unknown" : DeviceType)}";
        }
    }

    // Application class based on UML diagram
    public class NetworkApp
    {
        public int appId { get; set; }
        public string appName { get; set; }

        private NetworkMonitor _networkMonitor;

        public NetworkApp()
        {
            _networkMonitor = new NetworkMonitor();
        }

        public void open()
        {
            // Initialize application components
        }

        public void close()
        {
            // Close all application components
        }

        public void displayMainMenu()
        {
            // Display the main menu
        }

        public void notifySecurityUpdate(string update)
        {
            // Notify the user about security updates
        }

        public bool updateMacDatabase()
        {
            // Update MAC address vendor database
            return true;
        }

        public bool updateSecurityDefinitions()
        {
            // Update security definitions
            return true;
        }

        public void runScheduledScan()
        {
            // Run a scheduled network scan
            _networkMonitor.initiateSecurityScan(null);
        }
    }

    // User class based on UML diagram
    public class User
    {
        public int userId { get; set; }
        public string username { get; set; }
        public string passwordHash { get; set; }

        private SecurityManager _securityManager;

        public User()
        {
            _securityManager = new SecurityManager();
        }

        public bool login(string username, string password)
        {
            // Authenticate user
            return true;
        }

        public void logout()
        {
            // Log out the user
        }

        public void disconnectFromNetwork()
        {
            // Disconnect from the current network
        }

        public bool implementSecurityRecommendations(List<string> recommendations)
        {
            // Implement security recommendations
            return true;
        }

        public List<string> viewSecurityReports()
        {
            // View available security reports
            return new List<string>();
        }
    }

    // NetworkMonitor class based on UML diagram
    public class NetworkMonitor
    {
        public int monitorId { get; set; }

        private Network _currentNetwork;
        private NetworkScanner _scanner;

        public NetworkMonitor()
        {
            _scanner = new NetworkScanner();
        }

        public void monitorNetwork(Network network)
        {
            _currentNetwork = network;
            // Start monitoring the network
        }

        public SecurityReport initiateSecurityScan(Network network)
        {
            if (network == null && _currentNetwork != null)
            {
                network = _currentNetwork;
            }

            // Initiate a security scan on the network
            return _scanner.gatherSecurityInfo(network);
        }

        public bool restrictNetworkAccess(Network network)
        {
            // Restrict access to the network
            return true;
        }

        public void alertUser(User user, string message, string severity, Enum @enum)
        {
            // Alert the user about a security issue
        }

        public byte[] encryptPackets(byte[] data)
        {
            // Encrypt network packets
            return data;
        }

        public byte[] decryptPackets(byte[] encryptedData)
        {
            // Decrypt network packets
            return encryptedData;
        }

        public bool preventUnencryptedData(byte[] data)
        {
            // Prevent unencrypted data transmission
            return true;
        }

        public void logNetworkActivity(string activity)
        {
            // Log network activity
        }
    }

    // Network class based on UML diagram
    public class Network
    {
        public int networkId { get; set; }
        public string networkName { get; set; }
        public Enum networkType { get; set; }
        public string subnetMask { get; set; }
        public string gateway { get; set; }

        private List<Device> _connectedDevices = new List<Device>();

        public bool isConnected()
        {
            // Check if connected to this network
            return true;
        }

        public List<Device> getConnectedDevices()
        {
            // Get list of connected devices
            return _connectedDevices;
        }

        public SecurityReport scanNetwork()
        {
            // Scan the network for devices and security issues
            var scanner = new NetworkScanner();
            return scanner.gatherSecurityInfo(this);
        }
    }

    // Device class based on UML diagram
    public class Device
    {
        public string deviceId { get; set; }
        public string deviceName { get; set; }
        public string ipAddress { get; set; }
        public string macAddress { get; set; }
        public string operatingSystem { get; set; }
        public string firmwareVersion { get; set; }
        public bool isConnected { get; set; }

        public string getOperatingSystem()
        {
            // Get the operating system of the device
            return operatingSystem;
        }

        public string getFirmwareVersion()
        {
            // Get the firmware version of the device
            return firmwareVersion;
        }

        public bool updateFirmware(string newVersion)
        {
            // Update the firmware of the device
            return true;
        }
    }

    // NetworkScanner class based on UML diagram
    public class NetworkScanner
    {
        public int scannerId { get; set; }

        public SecurityReport gatherSecurityInfo(Network network)
        {
            // Gather security information about the network
            SecurityReport report = new SecurityReport();
            report.reportId = new Random().Next(1000, 9999);
            report.reportDate = DateTime.Now;

            // Scan for connected devices
            int deviceCount = countConnectedDevices(network);

            // Identify operating systems
            var osSummary = identifyOperatingSystems(network);

            // Check firmware versions
            var firmwareReport = reportFirmwareVersions(network);

            // Scan for security issues
            analyzeSecurityPatches("localhost");
            scanDhcpSpoofing(network);
            scanFakeServers(network);
            performDeepPacketInspection(network);

            return report;
        }

        public int countConnectedDevices(Network network)
        {
            // Count the number of devices connected to the network
            return network.getConnectedDevices().Count;
        }

        public Dictionary<string, string> identifyOperatingSystems(Network network)
        {
            // Identify operating systems of devices on the network
            var result = new Dictionary<string, string>();
            foreach (var device in network.getConnectedDevices())
            {
                result[device.ipAddress] = device.operatingSystem;
            }
            return result;
        }

        public Dictionary<string, string> reportFirmwareVersions(Network network)
        {
            // Report firmware versions of devices on the network
            var result = new Dictionary<string, string>();
            foreach (var device in network.getConnectedDevices())
            {
                result[device.ipAddress] = device.firmwareVersion;
            }
            return result;
        }

        public List<string> checkFirmwareUpdates(List<Device> devices)
        {
            // Check for firmware updates for devices
            return new List<string>();
        }

        public List<string> analyzeSecurityPatches(string host)
        {
            // Analyze security patches on the host
            return new List<string>();
        }

        public List<string> scanDhcpSpoofing(Network network)
        {
            // Scan for DHCP spoofing attacks
            return new List<string>();
        }

        public List<string> scanFakeServers(Network network)
        {
            // Scan for fake servers on the network
            return new List<string>();
        }

        public List<string> performDeepPacketInspection(Network network)
        {
            // Perform deep packet inspection on network traffic
            return new List<string>();
        }
    }

    // SecurityManager class based on UML diagram
    public class SecurityManager
    {
        public int managerId { get; set; }

        public List<string> suggestSecurityRecommendations(SecurityReport report)
        {
            // Suggest security recommendations based on the report
            return new List<string>();
        }

        public bool removeMaliciousDns(Network network)
        {
            // Remove malicious DNS settings
            return true;
        }

        public bool clearDnsCache()
        {
            // Clear DNS cache
            return true;
        }

        public string obfuscateIpAddress(Network network)
        {
            // Obfuscate IP address for privacy
            return "obfuscated-ip";
        }

        public string randomizeMacAddress(Device device)
        {
            // Randomize MAC address for privacy
            return "randomized-mac";
        }

        public bool mitigateTracking(Network network)
        {
            // Mitigate tracking attempts
            return true;
        }

        public List<string> monitorForAttacks(Network network)
        {
            // Monitor for network attacks
            return new List<string>();
        }

        public bool quarantineDevice(Device device)
        {
            // Quarantine a potentially malicious device
            return true;
        }

        public SecurityReport generateSecurityReport(Dictionary<string, Dictionary<string, object>> scanData)
        {
            // Generate a security report from scan data
            return new SecurityReport();
        }
    }

    // SecurityReport class based on UML diagram
    public class SecurityReport
    {
        public int reportId { get; set; }
        public DateTime reportDate { get; set; }
        public List<string> vulnerabilities { get; set; } = new List<string>();
        public Dictionary<string, string> deviceDetails { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> networkDetails { get; set; } = new Dictionary<string, string>();

        public string generateReport()
        {
            // Generate a formatted report
            return $"Security Report #{reportId}\nDate: {reportDate}\nVulnerabilities: {vulnerabilities.Count}";
        }
    }

    // MainWindow - UI implementation
    public partial class MainWindow : MetroWindow
    {
        private CancellationTokenSource _cancellationTokenSource;
        private ObservableCollection<NetworkDevice> _discoveredDevices = new ObservableCollection<NetworkDevice>();
        private Dictionary<string, string> _discoveredMacs = new Dictionary<string, string>();
        private object _lockObject = new object();

        // Properties for vulnerability counts
        private int _criticalVulnerabilities = 4;
        private int _mediumVulnerabilities = 3;
        private int _optionalVulnerabilities = 3;
        private int _totalDevicesFound = 0;

        // New class instances from UML diagram
        private NetworkApp _application;
        private NetworkMonitor _networkMonitor;
        private Network _currentNetwork;
        private SecurityManager _securityManager;

        // Flag to indicate whether nmap is available
        private bool _isNmapAvailable = false;

        public MainWindow()
        {
            InitializeComponent();

            try
            {
                // Check for required dependencies on startup
                CheckDependencies();

                // Initialize UML classes
                _application = new NetworkApp();
                _networkMonitor = new NetworkMonitor();
                _currentNetwork = new Network();
                _securityManager = new SecurityManager();

                // Initialize the device list with the sample data
                deviceListBox.ItemsSource = _discoveredDevices;

                // Update UI elements with initial values
                UpdateVulnerabilityCounts();
                deviceCountText.Text = $"Connected Devices (0)";
                scanStatusText.Text = "Ready to scan. Click 'New Scan' to begin.";
                scanProgressBar.Value = 0;
            }
            catch (Exception ex)
            {
                // Log the error and show a friendly message
                Debug.WriteLine($"Initialization error: {ex}");
                MessageBox.Show($"Error initializing application: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CheckDependencies()
        {
            try
            {
                // Check if nmap is available
                _isNmapAvailable = IsNmapAvailable();
                if (!_isNmapAvailable)
                {
                    MessageBox.Show("Nmap is not found in system PATH. Please install Nmap to use this application.",
                        "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Dependency check error: {ex}");
                MessageBox.Show("Error checking dependencies. Some features may not work properly.",
                    "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private bool IsNmapAvailable()
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "nmap";
                    process.StartInfo.Arguments = "--version";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    return output.Contains("Nmap version");
                }
            }
            catch
            {
                return false;
            }
        }

        private void UpdateVulnerabilityCounts()
        {
            // In a real implementation, you would analyze each device for vulnerabilities
            // This is just using the predefined sample values from the screenshot

            criticalVulnCountText.Text = _criticalVulnerabilities.ToString();
            mediumVulnCountText.Text = _mediumVulnerabilities.ToString();
            optionalVulnCountText.Text = _optionalVulnerabilities.ToString();

            // Update the scan status text
            int totalVulnerabilities = _criticalVulnerabilities + _mediumVulnerabilities + _optionalVulnerabilities;
            scanStatusText.Text = $"Scan complete. Found {_totalDevicesFound} devices and {totalVulnerabilities} vulnerabilities.";

            // Update device count text
            deviceCountText.Text = $"Connected Devices ({_totalDevicesFound})";
        }

        private void SetupDeviceList()
        {
            // Set the ItemsSource if not already done
            deviceListBox.ItemsSource = _discoveredDevices;

            // If you're using an ItemsControl instead of ListBox, add these properties:
            ((ItemsControl)deviceListBox).ItemTemplate = (DataTemplate)FindResource("DeviceItemTemplate");

            // Optional: Add event handler for expander events
            deviceListBox.AddHandler(Expander.ExpandedEvent, new RoutedEventHandler(Expander_Expanded));
        }

        private void Expander_Expanded(object sender, RoutedEventArgs e)
        {
            if (e.OriginalSource is Expander expander && expander.DataContext is NetworkDevice device)
            {
                // You could use this to log or trigger additional data loading when a device is expanded
                Debug.WriteLine($"Device details expanded: {device.IpAddress} ({device.DeviceType})");

                // Example: You could load additional device details when expanded
                // LoadAdditionalDeviceDetails(device);
            }
        }

        private async void LoadAdditionalDeviceDetails(NetworkDevice device)
        {
            // Example: This could run a more detailed scan for the specific device
            // Only run this if you need to fetch additional data when the user expands a device

            try
            {
                // Show loading indicator
                device.OperatingSystem = "Loading additional details...";
                RefreshDeviceList();

                // Run a more detailed scan or fetch additional information
                string additionalInfo = await Task.Run(() => GetDetailedDeviceInfo(device.IpAddress));

                // Update the device with additional information
                device.OperatingSystem += " " + additionalInfo;
                RefreshDeviceList();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading additional device details: {ex.Message}");
            }
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // If a scan is already running, cancel it
                if (_cancellationTokenSource != null)
                {
                    _cancellationTokenSource.Cancel();
                    _cancellationTokenSource = null;
                    UpdateScanButtonText("New Scan");
                    scanStatusText.Text = "Scan cancelled";
                    return;
                }

                // Clear previous results
                _discoveredDevices.Clear();
                _discoveredMacs.Clear();
                deviceListBox.ItemsSource = _discoveredDevices;
                _totalDevicesFound = 0;
                deviceCountText.Text = "Connected Devices (0)";

                // Set up cancellation token
                _cancellationTokenSource = new CancellationTokenSource();
                var token = _cancellationTokenSource.Token;

                // Update UI
                UpdateScanButtonText("Cancel Scan");
                scanStatusText.Text = "Initializing scan...";
                scanProgressBar.IsIndeterminate = true;
                scanProgressBar.Value = 0;

                await Task.Run(async () =>
                {
                    try
                    {
                        // Use Nmap to scan the network
                        var devicesFound = await ScanNetworkWithNmapAsync(token);

                        Debug.WriteLine($"Scan complete, found {devicesFound} devices");
                        UpdateStatus($"Network scan complete. Found {devicesFound} devices.");

                        // Explicitly check if we have devices before proceeding
                        if (devicesFound > 0 && !token.IsCancellationRequested)
                        {
                            UpdateStatus("Performing OS detection...");

                            // Make sure we're getting the latest device list
                            List<NetworkDevice> devicesToScan = new List<NetworkDevice>();
                            Dispatcher.Invoke(() => {
                                devicesToScan = _discoveredDevices.ToList();
                                Debug.WriteLine($"Preparing OS detection for {devicesToScan.Count} devices");
                            });

                            // Now run the OS detection
                            await DetectOperatingSystemsAsync(devicesToScan, token);
                        }
                        else
                        {
                            UpdateStatus("No devices found or scan was cancelled.");
                        }

                        Dispatcher.Invoke(() =>
                        {
                            // Final update of scan status
                            scanProgressBar.IsIndeterminate = false;
                            scanProgressBar.Value = 100;

                            // Update vulnerability counts and final status
                            UpdateVulnerabilityCounts();
                        });
                    }
                    catch (OperationCanceledException)
                    {
                        UpdateStatus("Scan cancelled");
                    }
                    catch (Exception ex)
                    {
                        UpdateStatus($"Error: {ex.Message}");
                        Debug.WriteLine($"Scan error details: {ex}");
                    }
                    finally
                    {
                        Dispatcher.Invoke(() =>
                        {
                            UpdateScanButtonText("New Scan");
                            scanProgressBar.IsIndeterminate = false;
                        });
                        _cancellationTokenSource = null;
                    }
                }, token);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Debug.WriteLine($"Button click error details: {ex}");
            }
        }

        // New method to scan the network using Nmap
        private async Task<int> ScanNetworkWithNmapAsync(CancellationToken token)
        {
            if (!_isNmapAvailable)
            {
                UpdateStatus("Nmap is not available. Please install Nmap to use this application.");
                return 0;
            }

            try
            {
                UpdateStatus("Getting network configuration...");

                // Get the default gateway of the active network interface
                string gateway = GetDefaultGateway();
                if (string.IsNullOrEmpty(gateway))
                {
                    UpdateStatus("Could not determine default gateway. Please check your network connection.");
                    return 0;
                }

                // Get the subnet from the gateway (assuming a /24 network)
                string subnet = gateway.Substring(0, gateway.LastIndexOf('.')) + ".0/24";

                UpdateStatus($"Starting Nmap scan of network {subnet}...");
                Debug.WriteLine($"Starting Nmap scan of network {subnet}");

                // Create a temporary file for Nmap output
                string tempFile = Path.GetTempFileName();

                using (Process process = new Process())
                {
                    // Set up Nmap process
                    process.StartInfo.FileName = "nmap";
                    // Use the requested command: nmap -T3 -F [IP]/24
                    // -T3: Normal timing template (balance between speed and accuracy)
                    // -F: Fast mode - scan fewer ports than the default scan
                    process.StartInfo.Arguments = $"-T3 -F {subnet} -oX \"{tempFile}\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;

                    // Log the command
                    Debug.WriteLine($"Executing: nmap {process.StartInfo.Arguments}");
                    UpdateStatus("Scanning network with Nmap...");

                    // Start the Nmap process
                    process.Start();

                    // Create a task to read the output
                    var outputTask = process.StandardOutput.ReadToEndAsync();
                    var errorTask = process.StandardError.ReadToEndAsync();

                    // Read output periodically to show progress
                    int progress = 10;
                    while (!process.HasExited && !token.IsCancellationRequested)
                    {
                        await Task.Delay(500, token);
                        progress = (progress + 2) % 90; // cycle between 10 and 90 percent
                        UpdateProgress(progress);
                        UpdateStatus($"Scanning network... This may take a minute.");
                    }

                    if (token.IsCancellationRequested)
                    {
                        try
                        {
                            if (!process.HasExited)
                                process.Kill();
                        }
                        catch { /* Ignore errors when killing process */ }

                        // Try to delete the temp file
                        try
                        {
                            if (File.Exists(tempFile))
                                File.Delete(tempFile);
                        }
                        catch { /* Ignore deletion errors */ }

                        throw new OperationCanceledException();
                    }

                    // Wait for the process to exit with a timeout
                    bool exited = await Task.Run(() => process.WaitForExit(60000), token); // 60 second timeout

                    if (!exited)
                    {
                        UpdateStatus("Nmap scan is taking too long. Terminating...");
                        try
                        {
                            process.Kill();
                        }
                        catch { /* Ignore errors when killing process */ }
                        return 0;
                    }

                    string output = await outputTask;
                    string error = await errorTask;

                    if (!string.IsNullOrEmpty(error) && !error.Contains("Completed"))
                    {
                        Debug.WriteLine($"Nmap error: {error}");
                        // If it's just a warning, we can continue
                        if (error.Contains("WARNING") || error.Contains("Note"))
                        {
                            Debug.WriteLine("Nmap reported warnings but scan may still be valid");
                        }
                        else
                        {
                            UpdateStatus($"Error running Nmap: {error}");
                            return 0;
                        }
                    }

                    // Check if the XML file exists and has data
                    if (!File.Exists(tempFile) || new FileInfo(tempFile).Length == 0)
                    {
                        UpdateStatus("Nmap did not generate any output. Scan may have failed.");
                        return 0;
                    }

                    // Parse the Nmap XML output
                    string xmlOutput = await File.ReadAllTextAsync(tempFile, token);
                    int devicesFound = ParseNmapXmlOutput(xmlOutput);

                    // Delete the temporary file
                    try
                    {
                        File.Delete(tempFile);
                    }
                    catch { /* Ignore deletion errors */ }

                    // Update the Network object with discovered devices
                    UpdateCurrentNetwork(devicesFound);

                    return devicesFound;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in Nmap scan: {ex}");
                UpdateStatus($"Error scanning network: {ex.Message}");
                return 0;
            }
        }

        private int ParseNmapXmlOutput(string xmlOutput)
        {
            try
            {
                // We're going to parse the XML manually for simplicity
                // In a real application, you might want to use XML parsing libraries

                UpdateStatus("Processing Nmap results...");

                int deviceCount = 0;

                // Extract all host blocks
                var hostMatches = Regex.Matches(xmlOutput, @"<host[^>]*>.*?</host>", RegexOptions.Singleline);

                foreach (Match hostMatch in hostMatches)
                {
                    string hostBlock = hostMatch.Value;

                    // Extract the IP address
                    Match ipMatch = Regex.Match(hostBlock, @"<address addr=""([^""]+)"" addrtype=""ipv4""");
                    if (!ipMatch.Success) continue;

                    string ipAddress = ipMatch.Groups[1].Value;

                    // Extract the MAC address if present
                    string macAddress = "Unknown";
                    Match macMatch = Regex.Match(hostBlock, @"<address addr=""([^""]+)"" addrtype=""mac""");
                    if (macMatch.Success)
                    {
                        macAddress = macMatch.Groups[1].Value;
                    }

                    // Extract vendor information if present
                    string vendor = "Unknown";
                    Match vendorMatch = Regex.Match(hostBlock, @"<address [^>]*vendor=""([^""]+)""");
                    if (vendorMatch.Success)
                    {
                        vendor = vendorMatch.Groups[1].Value;
                    }

                    // Extract hostname if present
                    string hostname = "N/A";
                    Match hostnameMatch = Regex.Match(hostBlock, @"<hostname name=""([^""]+)""");
                    if (hostnameMatch.Success)
                    {
                        hostname = hostnameMatch.Groups[1].Value;
                    }

                    // Extract status to make sure the host is up
                    Match statusMatch = Regex.Match(hostBlock, @"<status state=""([^""]+)""");
                    if (statusMatch.Success && statusMatch.Groups[1].Value.ToLower() == "up")
                    {
                        deviceCount++;

                        // Add this device to our collection
                        Dispatcher.Invoke(() =>
                        {
                            // Add the device only if it's not already in the list
                            if (!_discoveredDevices.Any(d => d.IpAddress == ipAddress))
                            {
                                AddDiscoveredDevice(ipAddress, macAddress, hostname, vendor);
                            }
                        });
                    }
                }

                Debug.WriteLine($"Parsed Nmap output: found {deviceCount} devices");
                return deviceCount;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error parsing Nmap output: {ex}");
                UpdateStatus($"Error parsing Nmap output: {ex.Message}");
                return 0;
            }
        }

        private void AddDiscoveredDevice(string ipAddress, string macAddress, string hostname = null, string vendor = null)
        {
            try
            {
                // If no vendor was provided, try to identify it from the MAC
                if (string.IsNullOrEmpty(vendor) || vendor == "Unknown")
                {
                    vendor = GetVendorFromMac(macAddress);
                }

                // Create the new device
                var device = new NetworkDevice
                {
                    IpAddress = ipAddress,
                    MacAddress = macAddress,
                    Hostname = hostname ?? "N/A",
                    Vendor = vendor,
                    OperatingSystem = "Detecting...",
                    DeviceType = "Unknown Device"
                };

                // Add to the list
                _discoveredDevices.Add(device);
                _discoveredMacs[ipAddress] = macAddress;

                // Update the device count
                _totalDevicesFound = _discoveredDevices.Count;
                deviceCountText.Text = $"Connected Devices ({_totalDevicesFound})";

                // Also add to the Device model from UML
                Device deviceModel = new Device
                {
                    deviceId = Guid.NewGuid().ToString(),
                    deviceName = hostname ?? "Unknown",
                    ipAddress = ipAddress,
                    macAddress = macAddress,
                    operatingSystem = "Detecting...",
                    firmwareVersion = "Unknown",
                    isConnected = true
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error adding device {ipAddress}: {ex.Message}");
            }
        }

        private string GetDefaultGateway()
        {
            try
            {
                // First, try to get the gateway from the active network interface
                NetworkInterface activeInterface = GetActiveNetworkInterface();
                if (activeInterface != null)
                {
                    foreach (GatewayIPAddressInformation gateway in activeInterface.GetIPProperties().GatewayAddresses)
                    {
                        if (gateway.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return gateway.Address.ToString();
                        }
                    }
                }

                // If that fails, try to get it from ipconfig
                return GetDefaultGatewayFromIpConfig();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error getting default gateway: {ex.Message}");
                return null;
            }
        }

        private string GetDefaultGatewayFromIpConfig()
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "ipconfig";
                    process.StartInfo.Arguments = "/all";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Look for the default gateway in the output
                    Match gatewayMatch = Regex.Match(output, @"Default Gateway[\s.]*:[\s.]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)");
                    if (gatewayMatch.Success)
                    {
                        return gatewayMatch.Groups[1].Value;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error running ipconfig: {ex.Message}");
            }

            return null;
        }

        private NetworkInterface GetActiveNetworkInterface()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(ni => ni.OperationalStatus == OperationalStatus.Up &&
                                     (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                                      ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet) &&
                                     ni.GetIPProperties().UnicastAddresses.Any(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork));
        }

        private void UpdateCurrentNetwork(int deviceCount)
        {
            // Update the Network object with the discovered network information
            NetworkInterface activeInterface = GetActiveNetworkInterface();
            if (activeInterface != null)
            {
                IPAddress localIp = GetLocalIPAddress(activeInterface);
                if (localIp != null)
                {
                    UnicastIPAddressInformation ipInfo = activeInterface.GetIPProperties().UnicastAddresses
                        .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (ipInfo != null)
                    {
                        _currentNetwork.networkId = new Random().Next(1000, 9999);
                        _currentNetwork.networkName = activeInterface.Name;
                        _currentNetwork.subnetMask = ipInfo.IPv4Mask.ToString();
                        _currentNetwork.gateway = GetDefaultGateway();
                    }
                }
            }
        }

        private IPAddress GetLocalIPAddress(NetworkInterface networkInterface)
        {
            return networkInterface.GetIPProperties().UnicastAddresses
                .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;
        }

        // Helper method to update scan button text
        private void UpdateScanButtonText(string text)
        {
            Dispatcher.Invoke(() =>
            {
                var iconChar = text == "New Scan" ? "↻" : "✕";

                StackPanel contentPanel = new StackPanel { Orientation = Orientation.Horizontal };
                contentPanel.Children.Add(new TextBlock { Text = iconChar, FontSize = 16, Margin = new Thickness(0, 0, 8, 0) });
                contentPanel.Children.Add(new TextBlock { Text = text });

                scanButton.Content = contentPanel;
            });
        }

        // Add this method to determine device type
        private string DetermineDeviceType(string ipAddress, string macAddress, string hostname,
                                         string vendor, string operatingSystem)
        {
            // Identify device type based on available information

            // Router/Modem identification
            if (hostname != null &&
                (hostname.ToLower().Contains("router") ||
                 hostname.ToLower().Contains("gateway") ||
                 hostname.ToLower().Contains("modem") ||
                 hostname.ToLower().Contains("ap")))
            {
                return "Router/Modem";
            }

            // Check vendor for router manufacturers
            if (vendor.Contains("Cisco") ||
                vendor.Contains("Huawei") ||
                vendor.Contains("D-Link") ||
                vendor.Contains("TP-Link") ||
                vendor.Contains("Netgear") ||
                vendor.Contains("Asus") ||
                vendor.Contains("Linksys") ||
                vendor.Contains("Aerohive"))
            {
                // Check if this is likely a router/gateway
                if (ipAddress.EndsWith(".1") || ipAddress.EndsWith(".254"))
                {
                    return "Router/Modem";
                }
            }

            // If we have OS information, use it for detection
            string os = operatingSystem?.ToLower() ?? "";

            // Check for mobile devices
            if (os.Contains("android") || vendor.Contains("Samsung") ||
                vendor.Contains("Xiaomi") || vendor.Contains("OnePlus") ||
                vendor.Contains("Huawei") && !ipAddress.EndsWith(".1"))
            {
                return "Android Phone";
            }

            if (os.Contains("ios") || os.Contains("iphone") ||
                (vendor.Contains("Apple") && !os.Contains("mac")))
            {
                return "iOS Device";
            }

            // Check for desktop/laptop OS
            if (os.Contains("windows"))
            {
                return "Windows PC";
            }

            if (os.Contains("linux") || os.Contains("ubuntu") ||
                os.Contains("debian") || os.Contains("fedora") ||
                os.Contains("red hat") || os.Contains("centos"))
            {
                return "Linux PC";
            }

            if (os.Contains("mac") || os.Contains("macos") ||
                (vendor.Contains("Apple") && !os.Contains("iphone") && !os.Contains("ios")))
            {
                return "Mac PC";
            }

            // Media devices
            if (vendor.Contains("Sony") || vendor.Contains("LG") ||
                hostname?.ToLower().Contains("tv") == true ||
                os.Contains("smart tv") || os.Contains("roku") ||
                os.Contains("chromecast"))
            {
                return "Media Device";
            }

            // IoT devices
            if (os.Contains("iot") || hostname?.ToLower().Contains("cam") == true ||
                hostname?.ToLower().Contains("sensor") == true ||
                hostname?.ToLower().Contains("smart") == true)
            {
                return "IoT Device";
            }

            // Skip port scanning if nmap is not available
            if (!_isNmapAvailable)
            {
                return "Unknown Device";
            }

            // Default case - make an educated guess based on port scanning
            try
            {
                return GetDeviceTypeFromPortsAsync(ipAddress).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error determining device type from ports: {ex.Message}");
                return "Unknown Device";
            }
        }

        private async Task<string> GetDeviceTypeFromPortsAsync(string ipAddress)
        {
            try
            {
                if (!_isNmapAvailable)
                {
                    return "Unknown Device";
                }

                // Create a temporary file for nmap output
                string tempFile = Path.GetTempFileName();

                // Run a quick port scan to identify common device ports
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "nmap";
                    // Scan typical ports that can help identify device types
                    // 22: SSH (common on Linux, networking devices)
                    // 80/443: HTTP/HTTPS (web interfaces)
                    // 445: SMB (Windows file sharing)
                    // 5555: Android Debug Bridge
                    // 8080: Alternative HTTP (often for media devices)
                    // 62078: iOS devices
                    process.StartInfo.Arguments = $"-Pn -T4 -F {ipAddress} -oN \"{tempFile}\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    await process.WaitForExitAsync();

                    // Read the output file
                    string output = "";
                    if (File.Exists(tempFile))
                    {
                        output = await File.ReadAllTextAsync(tempFile);
                        try { File.Delete(tempFile); } catch { /* Ignore deletion errors */ }
                    }

                    // Check for common port patterns
                    if (output.Contains("445/tcp") && output.Contains("open"))
                    {
                        return "Windows PC"; // SMB is strong indicator of Windows
                    }

                    if (output.Contains("22/tcp") && output.Contains("open"))
                    {
                        if (output.Contains("80/tcp") && output.Contains("open") &&
                            (ipAddress.EndsWith(".1") || ipAddress.EndsWith(".254")))
                        {
                            return "Router/Modem"; // SSH + HTTP + Gateway IP is likely a router
                        }
                        return "Linux PC"; // SSH alone is common on Linux
                    }

                    if (output.Contains("5555/tcp") && output.Contains("open"))
                    {
                        return "Android Phone"; // ADB port is Android-specific
                    }

                    if (output.Contains("62078/tcp") && output.Contains("open"))
                    {
                        return "iOS Device";
                    }

                    if ((output.Contains("8080/tcp") || output.Contains("80/tcp")) &&
                        output.Contains("open") && !output.Contains("22/tcp"))
                    {
                        // Web interface without SSH might be a media device or IoT
                        return "Smart Device";
                    }
                }

                return "Unknown Device";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in port scanning: {ex.Message}");
                return "Unknown Device";
            }
        }

        // Improved OS detection implementation
        private async Task DetectOperatingSystemsAsync(List<NetworkDevice> devices, CancellationToken token)
        {
            Debug.WriteLine($"Starting OS detection for {devices.Count} devices");
            int totalDevices = devices.Count;
            int processedDevices = 0;

            // Change the batch size based on device count to avoid overwhelming the system
            int batchSize = devices.Count <= 5 ? 1 :
                          devices.Count <= 10 ? 2 :
                          devices.Count <= 20 ? 3 : 5;

            // Process devices in batches
            for (int i = 0; i < devices.Count; i += batchSize)
            {
                if (token.IsCancellationRequested)
                    break;

                var batch = devices.Skip(i).Take(batchSize).ToList();
                Debug.WriteLine($"Processing OS detection batch of {batch.Count} devices");

                List<Task> osTasks = new List<Task>();

                foreach (var device in batch)
                {
                    if (token.IsCancellationRequested)
                        break;

                    osTasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            // Skip local host IP - we already know what OS it runs
                            if (device.IpAddress == "127.0.0.1")
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    int index = _discoveredDevices.IndexOf(device);
                                    if (index >= 0)
                                    {
                                        _discoveredDevices[index].OperatingSystem = Environment.OSVersion.ToString();
                                        _discoveredDevices[index].DeviceType = "This Computer";

                                        // Refresh the device list
                                        RefreshDeviceList();
                                    }
                                });
                                return;
                            }

                            // Log that we're starting OS detection for this device
                            Debug.WriteLine($"Detecting OS for {device.IpAddress}");

                            // Skip OS detection if nmap is not available
                            string os = "OS detection unavailable";
                            if (_isNmapAvailable)
                            {
                                // First try a fast OS guessing based on ports
                                string fastGuess = await GuessPlatformFromPortsAsync(device.IpAddress);
                                if (!string.IsNullOrEmpty(fastGuess) && fastGuess != "Unknown")
                                {
                                    os = fastGuess;
                                    Debug.WriteLine($"Fast OS detection for {device.IpAddress}: {os}");
                                }
                                else
                                {
                                    // If fast detection fails, try full nmap OS detection
                                    // Detect OS with nmap
                                    Debug.WriteLine($"Trying nmap OS detection for {device.IpAddress}");
                                    os = await DetectOSWithNmapAsync(device.IpAddress);
                                }
                            }
                            else
                            {
                                os = "Nmap not installed";
                            }

                            Debug.WriteLine($"OS detection result for {device.IpAddress}: {os}");

                            // Then determine device type
                            string deviceType = DetermineDeviceType(
                                device.IpAddress,
                                device.MacAddress,
                                device.Hostname,
                                device.Vendor,
                                os);

                            Dispatcher.Invoke(() =>
                            {
                                int index = _discoveredDevices.IndexOf(
                                    _discoveredDevices.FirstOrDefault(d => d.IpAddress == device.IpAddress));

                                if (index >= 0)
                                {
                                    _discoveredDevices[index].OperatingSystem = os;
                                    _discoveredDevices[index].DeviceType = deviceType;

                                    // Refresh the device list
                                    RefreshDeviceList();
                                }
                            });
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Detection error for {device.IpAddress}: {ex.Message}");

                            Dispatcher.Invoke(() =>
                            {
                                int index = _discoveredDevices.IndexOf(
                                    _discoveredDevices.FirstOrDefault(d => d.IpAddress == device.IpAddress));

                                if (index >= 0)
                                {
                                    _discoveredDevices[index].OperatingSystem = "Detection failed";
                                    _discoveredDevices[index].DeviceType = "Unknown Device";

                                    // Refresh the device list
                                    RefreshDeviceList();
                                }
                            });
                        }
                        finally
                        {
                            Interlocked.Increment(ref processedDevices);
                            UpdateStatus($"OS Detection: {processedDevices}/{totalDevices} devices processed");
                        }
                    }, token));
                }

                try
                {
                    // Wait for completion with a timeout to prevent hanging
                    var timeoutTask = Task.Delay(30000, token); // 30 second timeout per batch
                    var completedTask = await Task.WhenAny(Task.WhenAll(osTasks), timeoutTask);

                    if (completedTask == timeoutTask && !token.IsCancellationRequested)
                    {
                        Debug.WriteLine("OS detection batch timed out");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error waiting for OS detection tasks: {ex.Message}");
                }

                // Add a delay between batches to give the system a break
                if (i + batchSize < devices.Count && !token.IsCancellationRequested)
                {
                    await Task.Delay(2000, token);
                }
            }
        }

        // Fast OS detection by checking for open ports
        private async Task<string> GuessPlatformFromPortsAsync(string ipAddress)
        {
            try
            {
                // Common ports that indicate specific platforms
                Dictionary<int, string> platformPorts = new Dictionary<int, string>
        {
            { 445, "Windows" },       // SMB
            { 139, "Windows" },       // NetBIOS
            { 135, "Windows" },       // RPC
            { 3389, "Windows" },      // RDP
            { 22, "Linux/Unix" },     // SSH
            { 5900, "Linux/Unix" },   // VNC
            { 5353, "Apple" },        // mDNS
            { 548, "Apple" },         // AFP
            { 62078, "iOS Device" },  // iOS devices
            { 8080, "Android or IoT" } // Common on Android or IoT
        };

                List<Task<bool>> portTasks = new List<Task<bool>>();
                Dictionary<int, Task<bool>> portResults = new Dictionary<int, Task<bool>>();

                // Try to connect to each port with a short timeout
                foreach (var port in platformPorts.Keys)
                {
                    var task = CheckPortAsync(ipAddress, port);
                    portResults[port] = task;
                    portTasks.Add(task);
                }

                // Wait for all port checks to complete
                await Task.WhenAll(portTasks);

                // Check results and determine the platform
                foreach (var pair in portResults.OrderByDescending(kv => platformPorts[kv.Key]))
                {
                    int port = pair.Key;
                    bool isOpen = await pair.Value;

                    if (isOpen)
                    {
                        // Special case for SSH, which could be Windows, Linux or Mac
                        if (port == 22)
                        {
                            // Check windows-specific ports alongside SSH
                            bool hasSmb = await CheckPortAsync(ipAddress, 445);
                            bool hasRpc = await CheckPortAsync(ipAddress, 135);

                            if (hasSmb || hasRpc)
                            {
                                return "Windows with SSH";
                            }

                            // Check Apple-specific ports alongside SSH
                            bool hasBonjour = await CheckPortAsync(ipAddress, 5353);
                            bool hasAfp = await CheckPortAsync(ipAddress, 548);

                            if (hasBonjour || hasAfp)
                            {
                                return "macOS";
                            }

                            return "Linux/Unix";
                        }

                        return platformPorts[port];
                    }
                }

                return "Unknown";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error guessing platform from ports: {ex.Message}");
                return "Unknown";
            }
        }

        // Helper method to check if a port is open
        private async Task<bool> CheckPortAsync(string ipAddress, int port)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    // Set a short timeout
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(200)) == connectTask)
                    {
                        return client.Connected;
                    }
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        private void RefreshDeviceList()
        {
            if (deviceListBox.ItemsSource != null)
            {
                CollectionViewSource.GetDefaultView(deviceListBox.ItemsSource).Refresh();
            }
        }

        // Improved nmap OS detection method
        private async Task<string> DetectOSWithNmapAsync(string ipAddress)
        {
            try
            {
                if (!_isNmapAvailable)
                {
                    return "Nmap not available";
                }

                // Create a temporary file for output
                string tempFile = Path.GetTempFileName();

                // Run Nmap with OS detection - improved arguments
                using (Process process = new Process())
                {
                    // If nmap is in your PATH, use this:
                    process.StartInfo.FileName = "nmap";

                    // Enhanced arguments for better OS detection:
                    // -O: Enable OS detection
                    // -T4: Faster timing template
                    // --osscan-guess: Guess OS more aggressively
                    // -Pn: Treat all hosts as online (skip host discovery)
                    // --max-os-tries=1: Limit OS detection attempts to speed up scan
                    // -p-: Scan all ports
                    process.StartInfo.Arguments = $"-O -T4 --osscan-guess -Pn --max-os-tries=1 -p22,80,443,445,3389 {ipAddress} -oN \"{tempFile}\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;

                    Debug.WriteLine($"Starting nmap with args: {process.StartInfo.Arguments}");

                    try
                    {
                        process.Start();

                        // Read output streams (useful for debugging)
                        string stdOutput = await process.StandardOutput.ReadToEndAsync();
                        string stdError = await process.StandardError.ReadToEndAsync();

                        // Set a timeout for nmap operation
                        bool exited = await Task.Run(() => process.WaitForExit(20000)); // 20 second timeout

                        if (!exited)
                        {
                            Debug.WriteLine("Nmap process timed out, killing process");
                            try { process.Kill(); } catch { }
                            return "Nmap scan timed out";
                        }

                        // Read the output file if it exists
                        if (File.Exists(tempFile))
                        {
                            string output = await File.ReadAllTextAsync(tempFile);
                            Debug.WriteLine($"Nmap output file size: {output.Length} bytes");

                            // Delete temporary file
                            try { File.Delete(tempFile); } catch { /* Ignore deletion errors */ }

                            // First parse the file output
                            string result = ParseNmapOsOutput(output);

                            // If proper OS not detected from file, try parsing from stdout
                            if (result == "OS not detected" && !string.IsNullOrWhiteSpace(stdOutput))
                            {
                                result = ParseNmapOsOutput(stdOutput);
                            }

                            return result;
                        }

                        // If temp file doesn't exist, try parsing from stdout
                        if (!string.IsNullOrWhiteSpace(stdOutput))
                        {
                            Debug.WriteLine($"Nmap stdout size: {stdOutput.Length} bytes");
                            return ParseNmapOsOutput(stdOutput);
                        }

                        return "OS detection failed";
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Error executing nmap: {ex.Message}");
                        return "Error executing nmap";
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error detecting OS: {ex.Message}");
                return "Error: " + ex.Message;
            }
        }

        private string ParseNmapOsOutput(string nmapOutput)
        {
            try
            {
                // First, normalize line endings
                nmapOutput = nmapOutput.Replace("\r\n", "\n");

                // Look for OS detection lines
                string[] lines = nmapOutput.Split('\n');

                // First try to find "OS details:" line which has more specific information
                string osDetailsPattern = @"OS details: (.+)";
                foreach (string line in lines)
                {
                    Match match = Regex.Match(line, osDetailsPattern);
                    if (match.Success)
                    {
                        return match.Groups[1].Value.Trim();
                    }
                }

                // Try to find Aggressive OS guesses
                string osGuessPattern = @"Aggressive OS guesses: (.+)";
                foreach (string line in lines)
                {
                    Match match = Regex.Match(line, osGuessPattern);
                    if (match.Success)
                    {
                        string guesses = match.Groups[1].Value.Trim();
                        // Often gives multiple guesses with percentages - take the highest one
                        if (guesses.Contains("("))
                        {
                            return guesses.Split('(')[0].Trim();
                        }
                        return guesses;
                    }
                }

                // If no OS details found, try to find "OS:" line which has less specific information
                string osPattern = @"OS: (.+)";
                foreach (string line in lines)
                {
                    Match match = Regex.Match(line, osPattern);
                    if (match.Success && !line.Contains("OS CPE:") && !line.Contains("OS details:"))
                    {
                        return match.Groups[1].Value.Trim();
                    }
                }

                // Check for "Running" or "Running:" lines
                foreach (string line in lines)
                {
                    if (line.Contains("Running:") || line.Contains("Running (JUST GUESSING):"))
                    {
                        string[] parts = line.Split(new[] { "Running:", "Running (JUST GUESSING):" }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 0)
                        {
                            return parts[parts.Length - 1].Trim();
                        }
                    }
                }

                // If "OS CPE:" line is found, extract the OS from the CPE format
                string cpePattern = @"OS CPE: (.+)";
                foreach (string line in lines)
                {
                    Match match = Regex.Match(line, cpePattern);
                    if (match.Success)
                    {
                        string cpe = match.Groups[1].Value.Trim();
                        // CPE format: cpe:/o:vendor:product:version
                        string[] parts = cpe.Split(':');
                        if (parts.Length >= 4)
                        {
                            return $"{parts[2]} {parts[3]}";
                        }
                        return cpe;
                    }
                }

                // Look for "Device type:" which can give some basic info
                string devicePattern = @"Device type: (.+)";
                foreach (string line in lines)
                {
                    Match match = Regex.Match(line, devicePattern);
                    if (match.Success)
                    {
                        return "Device: " + match.Groups[1].Value.Trim();
                    }
                }

                // Check for common OS keywords in any part of the output
                string[] osKeywords = { "Windows", "Linux", "Mac OS", "macOS", "iOS", "Android",
                               "Unix", "FreeBSD", "OpenBSD", "Solaris", "Ubuntu", "Debian" };

                foreach (string keyword in osKeywords)
                {
                    foreach (string line in lines)
                    {
                        if (line.Contains(keyword) && !line.StartsWith("#") && !line.StartsWith("# "))
                        {
                            // Try to extract a reasonable OS name with context
                            int index = line.IndexOf(keyword);
                            int endIndex = line.IndexOf(',', index);
                            if (endIndex == -1) endIndex = line.IndexOf(')', index);
                            if (endIndex == -1) endIndex = line.IndexOf('(', index);
                            if (endIndex == -1) endIndex = line.Length;

                            int length = Math.Min(30, endIndex - index);
                            if (length > 0)
                                return line.Substring(index, length).Trim();
                        }
                    }
                }

                return "OS not detected";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error parsing Nmap output: {ex.Message}");
                return "Parsing error: " + ex.Message;
            }
        }

        private string GetDetailedDeviceInfo(string ipAddress)
        {
            return "Additional details loaded";
        }

        private void UpdateStatus(string message)
        {
            Dispatcher.Invoke(() =>
            {
                scanStatusText.Text = message;
            });
        }

        private void UpdateProgress(double value)
        {
            Dispatcher.Invoke(() =>
            {
                scanProgressBar.IsIndeterminate = false;
                scanProgressBar.Value = value;
            });
        }

        private string GetVendorFromMac(string macAddress)
        {
            if (string.IsNullOrEmpty(macAddress) || macAddress.Length < 8)
                return "Unknown";

            string oui = macAddress.Replace(":", "").Substring(0, 6).ToUpper();

            Dictionary<string, string> vendorDict = new Dictionary<string, string>
            {
                { "FCFBFB", "Apple" },
                { "002241", "Apple" },
                { "000C29", "VMware" },
                { "001C42", "Parallels" },
                { "000569", "VMware" },
                { "001A11", "Google" },
                { "7CEBEA", "Samsung" },
                { "F81EDF", "Apple" },
                { "3497FB", "Cisco" },
                { "3CD92B", "Hewlett Packard" },
                { "9C5D12", "Aerohive" }
            };

            if (vendorDict.TryGetValue(oui, out string vendor))
                return vendor;

            return "Unknown";
        }
    }
}