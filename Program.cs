using System;
using System.Collections.Generic;
using System.Device.Gpio;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Server;
using MQTTnet;
using Microsoft.Data.Sqlite;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using System.Net.WebSockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Processing; // <─── INJECT THIS LINE TO ENABLE THE MUTATE METHOD!


class Program
{
    static async Task Main(string[] args)
    {
        string pkiRoot = Environment.GetEnvironmentVariable("OPC_UA_PKI_ROOT")  ?? System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "pki");
        string bindIp = Environment.GetEnvironmentVariable("OPC_UA_BIND_IP") ?? "127.0.0.1";
        string bindPort = Environment.GetEnvironmentVariable("OPC_UA_BIND_PORT") ?? "4840";
        Console.WriteLine($"[SYSTEM INITIALIZATION] Target PKI Root set to: {pkiRoot}");
        string[] requiredStores = { "own", "trusted", "rejected", "issuer" };

        foreach (string store in requiredStores)
        {
            string targetDirectory = System.IO.Path.Combine(pkiRoot, store);
            
            if (!System.IO.Directory.Exists(targetDirectory))
            {
                // This physically generates the missing subfolder on disk
                System.IO.Directory.CreateDirectory(targetDirectory);
                Console.WriteLine($"[SYSTEM PROVISIONING] Successfully created directory: {targetDirectory}");
            }
        }
        Console.WriteLine("=========================================");
        Console.WriteLine(" INITIALIZING SECURED OPC UA GATEWAY     ");
        Console.WriteLine("=========================================");

        var server = new AggregationOpcServer();

        ApplicationConfiguration config = new ApplicationConfiguration()
        {
            ApplicationName = "Pi_Secured_Gateway",
            ApplicationType = ApplicationType.Server,
            ApplicationUri = "urn:localhost:IndustrialEdge:PiSecuredGateway",
            ProductUri = "http://industrialedge.org",
            ServerConfiguration = new ServerConfiguration()
            {
                BaseAddresses = new StringCollection {$"opc.tcp://{bindIp}:{bindPort}"},
                AlternateBaseAddresses = new StringCollection(), 
                
                SecurityPolicies = 
                { 
                    new ServerSecurityPolicy() 
                    { 
                        SecurityMode = MessageSecurityMode.SignAndEncrypt, 
                        SecurityPolicyUri = SecurityPolicies.Basic256Sha256 
                    }
                }
            },
            SecurityConfiguration = new SecurityConfiguration()
            {
                // FIXED: Direct the internal engine to use a visible, local project folder structure instead of system environment variables
                ApplicationCertificate = new CertificateIdentifier() 
                { 
                    StoreType = "Directory", 
                    StorePath = System.IO.Path.Combine(pkiRoot, "own"), 
                    SubjectName = "CN=Pi_Secured_Gateway, O=IndustrialEdge"
                },
                TrustedPeerCertificates = new CertificateTrustList() 
                {
                    StoreType = "Directory",
                    StorePath = System.IO.Path.Combine(pkiRoot, "trusted") 
                },
                RejectedCertificateStore = new CertificateTrustList() 
                {
                    StoreType = "Directory",
                    StorePath = System.IO.Path.Combine(pkiRoot, "rejected")
                },
                TrustedIssuerCertificates = new CertificateTrustList() 
                {
                    StoreType = "Directory", 
                    StorePath = System.IO.Path.Combine(pkiRoot, "issuer") 
                },
                AutoAcceptUntrustedCertificates = false 
            },
            TransportQuotas = new TransportQuotas() { OperationTimeout = 15000 },
            TraceConfiguration = new TraceConfiguration() { DeleteOnLoad = true }
        };

        config.CertificateValidator.CertificateValidation += (validator, args) =>
        {
            // If the certificate is already marked valid by the trust list, let it pass
            if (args.Error == null || args.Error.StatusCode == Opc.Ua.StatusCodes.Good)
            {
                args.Accept = true;
            }
            else
            {
                // For security validation monitoring, log the untrusted connection try
                Console.WriteLine($"[SECURITY ALERT] Rejecting untrusted client certificate: {args.Certificate.SubjectName.Name}");
                args.Accept = false; // Block unverified clients in production mode
            }
        };
        
        Console.WriteLine($"The server is listening on port {bindPort}");

        await config.ValidateAsync(ApplicationType.Server);
        
        ApplicationInstance application = new ApplicationInstance() 
        { 
            ApplicationName = "Pi_Secured_Gateway", 
            ApplicationType = ApplicationType.Server, 
            ApplicationConfiguration = config 
        };

        Console.WriteLine("[SECURITY ENGINE] Validating X.509 certificates...");
        
        // This plural method will now cleanly forge the local directory certificates without environment path limits
        bool certsOk = await application.CheckApplicationInstanceCertificatesAsync(true).ConfigureAwait(false);

        if (!certsOk)
        {
            throw new Exception("Cryptographic identity validation failed. Application cannot establish secure roots.");
        }

        string pkiPath = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "pki", "own");
        string certsPath = pkiPath + "/certs";
        string keyPath = pkiPath + "/private";
        if (!System.IO.Directory.Exists(pkiPath))
        {
            System.IO.Directory.CreateDirectory(pkiPath);
            System.Console.WriteLine($"[DEV OPS] Local PKI sandbox container directory generated at: {pkiPath}");
        }
        else
        {
            Console.WriteLine($"Onwer file is in {pkiPath}");
            if (System.IO.Directory.Exists(certsPath))
            {
                Console.WriteLine($"Certs file is in {certsPath}");
                string[] certsFiles = System.IO.Directory.GetFiles(certsPath, "*.*", System.IO.SearchOption.AllDirectories);
                foreach (string file in certsFiles)
                {
                    Console.WriteLine($"   [FILE] -> {file}");
                }
                Console.WriteLine($"Certs file is in {keyPath}");
                string[] keyFiles = System.IO.Directory.GetFiles(keyPath, "*.*", System.IO.SearchOption.AllDirectories);                 
                foreach (string file in keyFiles)
                {
                     Console.WriteLine($"   [FILE] -> {file}");
                }
            }
        }

        string issuerFolderLocation = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "pki", "issuer");
        if (!System.IO.Directory.Exists(issuerFolderLocation))
        {
            System.IO.Directory.CreateDirectory(issuerFolderLocation);
            Console.WriteLine($"[DEV OPS] Container issuer PKI paths successfully initialized at: {issuerFolderLocation}");
        }

        Console.WriteLine("Starting network communication doors...");
        await application.StartAsync(server);

        _ = Task.Run(async () => 
        {
            using var httpClient = new System.Net.Http.HttpClient();
            Console.WriteLine("[CLUSTER BUS] Asynchronous Hardware Distribution Engine Active.");

            while (true)
            {
                try
                {
                    // 1. Grab the latest sliding time-series metrics from your Node Manager
                    float currentVoltage = CustomNodeManager.LatestLiveVoltage; 
                    
                    // 2. Package data for your ESPRESSObin Central Message Broker
                    var clusterPayload = new { voltage = currentVoltage, machine = "Pi_Secured_Gateway" };
                    var jsonContent = new System.Net.Http.StringContent(
                        System.Text.Json.JsonSerializer.Serialize(clusterPayload), 
                        System.Text.Encoding.UTF8, 
                        "application/json"
                    );

                    // 3. Fire metrics up to the ESPRESSObin routing coordinates over the switch
                    await httpClient.PostAsync("http://192.168.8", jsonContent);
                }
                catch (Exception ex)
                {
                    // Logs network timeouts silently inside your soc_security_audit file
                    File.AppendAllText("soc_security_audit.log", $"[NET_WARN] Cluster sync dropped: {ex.Message}\n");
                }

                await Task.Delay(100); // 10Hz synchronization speed to prevent network starvation
            }
        });

        _ = Task.Run(async () => await StartWebHostAsync());        

        Console.WriteLine("\n=========================================");
        Console.WriteLine(" SUCCESS: Secure OPC UA Server is Live!  ");
        Console.WriteLine(" Endpoint URL: opc.tcp://127.0.0.1:48400 ");
        Console.WriteLine(" Encryption Enforced: Basic256Sha256     ");
        Console.WriteLine("=========================================");
        Console.WriteLine("Press Ctrl+C to terminate gateway network context.");

        while (true) 
        {
            await Task.Delay(1000);
        }
    }

    private static async Task StartWebHostAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(options =>
        {
            // Bind to all incoming network interfaces on port 5000 inside your Opal firewall subnet
            options.Listen(System.Net.IPAddress.Any, 5000, listenOptions =>
            {
                // Support both HTTP/1.1 (WebSockets) and HTTP/2 (gRPC) on the exact same port!
                listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
            });

            options.Listen(System.Net.IPAddress.Any, 5001, listenOptions =>
            {
                listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2;
            });
        });
        builder.Services.AddGrpc();

        builder.Services
            .AddGraphQLServer()
            .AddQueryType<SCADAGraphQueryResolver>();

        var app = builder.Build();

        app.UseRouting();

        app.UseWebSockets();
        app.Map("/ws", async context =>
        {
            if (context.WebSockets.IsWebSocketRequest)
            {
                using var webSocket = await context.WebSockets.AcceptWebSocketAsync();
                CustomNodeManager.RegisterWebClient(webSocket);
                Console.WriteLine("[WEB SERVER] Connected: Active HMI React Client Joined.");
                
                var buffer = new byte[1024 * 4];
                while (webSocket.State == WebSocketState.Open)
                {
                    var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                    if (result.MessageType == WebSocketMessageType.Close) break;
                }
                CustomNodeManager.UnregisterWebClient(webSocket);
            }
        });

        app.MapGrpcService<SCADABinaryTransmissionService>();
        Console.WriteLine("[SCADA CORE] gRPC Binary Transmission endpoint successfully mounted on HTTP/2 wire."); 

        // MAP THE EXPLICIT GRAPHQL ENDPOINT CHANNEL PATH ON THE WIRE
        app.MapGraphQL("/graphql");
        Console.WriteLine("[SCADA CORE] GraphQL Query Engine channel successfully mounted on /graphql wire.");
       

        await app.RunAsync();
    }
}

public class AggregationOpcServer : StandardServer
{
    private CustomNodeManager? _nodeManager;

    public AggregationOpcServer()
    {
        Console.WriteLine("[SERVER INITIALIZATION] AggregationOpcServer class constructor triggered.");
    }

    protected override MasterNodeManager CreateMasterNodeManager(IServerInternal server, ApplicationConfiguration configuration)
    {
        Console.WriteLine("Initizaling the address space");
        _nodeManager = new CustomNodeManager(server, configuration);
        return new MasterNodeManager(server, configuration, null, new INodeManager[] { _nodeManager });
    }
}

public class CustomNodeManager : CustomNodeManager2
{
    private BaseDataVariableState? _buttonNode;
    private BaseDataVariableState? _voltageNode;

    // --- TASK A: The Live Corporate AI Anomaly Feedback Node ---
    private BaseDataVariableState? _aiScoreNode;

    private GpioController _gpio;
    private int _buttonPin = 22; 
    private Timer? _pollingTimer;
    private string _lastStatus = "RELEASED"; 

    private IMqttClient? _mqttClient;

    // --- WEEK 8 CONFIGURATION: The path to our local flat database file footprint ---
    private string _dbConnectionString = "Data Source=substation_data.db;";

    // --- MONTH 3 AI VARIABLES ---
    // This session container will hold our pre-compiled neural network in local RAM
    private InferenceSession? _aiSession;
    private string _modelFilePath = "substation_model.onnx";

    private Microsoft.ML.OnnxRuntime.InferenceSession? _faceAiSession;
    private readonly string _modelPath = "version-RFB-320.onnx";

    private Iot.Device.Arduino.ArduinoBoard? _arduinoUno;
    private System.Device.Gpio.GpioController? _arduinoGpio;
    private string _arduinoPortName = "/dev/ttyACM0"; // Default Linux USB Serial port map token
    private int _greenLedPin = 8; // Panel Secure Marker Component
    private int _redLedPin = 13;   // Anomaly Alert Marker Component

    private System.Threading.Tasks.Task? _videoCaptureTask;
    private System.Threading.CancellationTokenSource? _videoCts;
    private int _targetWidth = 224;  // Standard input dimension width for deep learning models
    private int _targetHeight = 224; // Standard input dimension height for deep learning models

    private static readonly List<WebSocket> _activeWebSockets = new List<WebSocket>();
    private static readonly object _lockObject = new object();

    public static void RegisterWebClient(WebSocket socket) { lock(_lockObject) { _activeWebSockets.Add(socket); } }
    public static void UnregisterWebClient(WebSocket socket) { lock(_lockObject) { _activeWebSockets.Remove(socket); } }

    public static float LatestLiveVoltage = 0.0f;
    public static double LatestAnomalyScore = 0.0;
    public static string LatestBase64Image = "data:image/jpeg;base64,...";

    public static SCADATimeSeriesRingBuffer GridVoltageTimeSeries = new SCADATimeSeriesRingBuffer(50);

    public CustomNodeManager(IServerInternal server, ApplicationConfiguration configuration) 
        : base(server, configuration, "http://opcfoundation.org")
    {
        Console.WriteLine("Successfully access the node manager");
        Console.WriteLine("Grabbing GPIO pins");
        _gpio = new GpioController();
        Console.WriteLine("Successfully access the GPIO controller");
        Console.WriteLine("Opening the pin...");
        _gpio.OpenPin(_buttonPin, PinMode.Input);
        Console.WriteLine("Successfully open the pin");
        Task.Run(async () =>
        {
            try
            {
                Console.WriteLine("[ASYNC BOOT] Offloading heavy hardware and database initialization paths...");
                    
                // Move your synchronous calls inside this isolated thread context
                InitializeDatabase();
                InitializeEdgeAI();

               // await ConnectArduinoHardwareAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ASYNC BOOT ERROR] Background provisioning failed: {ex.Message}");
            }
        });
    }
    private async Task ConnectArduinoHardwareAsync()
    {    
        int maxAttempts = 5;
        int currentAttempt = 1;
        bool hardwareLinked = false;

        while (currentAttempt <= maxAttempts && !hardwareLinked)
        {
            try
            {
                Console.WriteLine($"[PURE C# LINK] Establishing Direct Actuator Tunnel (Attempt {currentAttempt}/{maxAttempts})...");
                    
                // 1. If a previous failed session exists, force-close and dispose it to clean system memory
                if (_arduinoUno != null) { _arduinoGpio?.Dispose(); _arduinoUno.Dispose(); }

                // 2. Open a completely fresh Firmata pipeline connection over the serial wire [1.1]
                _arduinoUno = new Iot.Device.Arduino.ArduinoBoard(_arduinoPortName, 57600);
                    
                // 3. Give the hardware a short micro-pause to stabilize the physical serial buffer
                await Task.Delay(500);

                // 4. Extract our virtual GPIO driver controller map natively
                _arduinoGpio = _arduinoUno.CreateGpioController();

                // 5. Defensive verification check: Ensure the framework registers our digital capability limits
                // On an Arduino Uno, physical pin numbers 12 and 13 are valid indices.
                if (_arduinoGpio != null)
                {
                    // Open your output tracks natively
                    _arduinoGpio.OpenPin(_greenLedPin, System.Device.Gpio.PinMode.Output);
                    _arduinoGpio.OpenPin(_redLedPin, System.Device.Gpio.PinMode.Output);
                        
                    // Set our safe default operational state
                    _arduinoGpio.Write(_greenLedPin, System.Device.Gpio.PinValue.High); // Green LED On
                    _arduinoGpio.Write(_redLedPin, System.Device.Gpio.PinValue.Low);   // Red LED Off
                        
                    hardwareLinked = true; // Handshake successfully locked with zero exceptions!
                    Console.WriteLine("[PURE C# LINK] Success: Remote Arduino Actuator Plane fully operational!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HARDWARE WARNING] Handshake dropped on attempt {currentAttempt}: {ex.Message}");
                currentAttempt++;
                    
                // Exponential backoff pause: Wait slightly longer on each failed pass to let the chip settle
                await Task.Delay(1000 * currentAttempt); 
            }
        }
    }


    private void InitializeFaceDetection()
    {
        try
        {
            Console.WriteLine("[AI ENGINE] Loading pre-trained UltraFace neural network weights into RAM...");
            _faceAiSession = new Microsoft.ML.OnnxRuntime.InferenceSession(_modelPath);
            Console.WriteLine("[AI ENGINE] ONNX Runtime execution session successfully initialized on the edge hardware.");
        }
        catch (System.Exception ex)
        {
            Console.WriteLine($"[AI CRITICAL ERROR] Failed to initialize neural network engine: {ex.Message}");
        }
    }

    // --- MONTH 3 AI INITIALIZATION ENGINE ---
    // Pre-loads our deep learning mathematical model directly into memory on boot-up [1.1]
    private void InitializeEdgeAI()
    {
        try
        {
            // Real-world practice requires the physical model file to exist on disk.
            // For this structural validation phase, we establish a clean diagnostic check.
            if (System.IO.File.Exists(_modelFilePath))
            {
                _aiSession = new InferenceSession(_modelFilePath);
                Console.WriteLine("[EDGE AI] Success: Neural network layers loaded into memory.");
            }
            else
            {
                Console.WriteLine("[EDGE AI] Warning: substation_model.onnx file not detected on disk.");
                Console.WriteLine("[EDGE AI] Action: Running in AI Simulation bypass mode until Week 10 model compilation.");
            }
        }
        catch (Exception ex) { Console.WriteLine($"AI Engine initialization failure: {ex.Message}"); }
    }

    // --- TASK B & C: THE LIVE EDGE INFERENCE EVALUATION PIPELINE ---
    // Unpacks runtime numbers, shapes the matrix tensor, and executes the ONNX computational tree model
    private double RunLiveInference(float currentVoltage, float currentButtonState)
    {
        if (_aiSession == null) return 0.0;

        try
        {
            // Forge the 1x2 multidimensional data matrix template shape expected by our model
            var inputTensor = new DenseTensor<float>(new[] { 1, 2 });
            inputTensor[0, 0] = currentVoltage;
            inputTensor[0, 1] = currentButtonState;

            // Pack the tensor into a named delivery box matching our python definition token string
            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor("input_tensor", inputTensor)
            };

            // Run the raw matrix math calculations directly on the Pi's hardware silicon
            using (var results = _aiSession.Run(inputs))
            {
                foreach (var output in results)
                {
                    // Intercept the prediction classification markers returned by the tree forest
                    if (output.Name == "label" || output.Name == "anomaly_score")
                    {
                        var outputData = output.AsTensor<long>(); // Isolation Forest outputs integer tracking arrays
                        // In scikit-learn Isolation Forest: 1 means normal, -1 means an out-of-bounds anomaly
                        return outputData.GetValue(0) == -1 ? 1.0 : 0.0;
                    }
                }
            }
        }
        catch (Exception ex) { Console.WriteLine($"Live inference computation drop: {ex.Message}"); }
        return 0.0;
    }

    // --- WEEK 8 INITIALIZATION ENGINE ---
    // Carves out our immutable, append-only time-series data table layout
    private void InitializeDatabase()
    {
        try
        {
            using (var connection = new SqliteConnection(_dbConnectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    CREATE TABLE IF NOT EXISTS HistoricalTelemetry (
                        Timestamp TEXT NOT NULL,
                        NodeId TEXT NOT NULL,
                        Value TEXT NOT NULL
                    );";
                command.ExecuteNonQuery();
                Console.WriteLine("[DATA LAKE] Local database engine initialized successfully.");
            }
        }
        catch (Exception ex) { Console.WriteLine($"Database initialization crash: {ex.Message}"); }
    }

    // --- WEEK 8 LOGGING CORE ---
    // Takes your live runtime metrics and appends a permanent timestamped line to disk
    private void LogToDataLake(string nodeId, string value)
    {
        try
        {
            using (var connection = new SqliteConnection(_dbConnectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = "INSERT INTO HistoricalTelemetry (Timestamp, NodeId, Value) VALUES ($time, $id, $val);";
                command.Parameters.AddWithValue("$time", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
                command.Parameters.AddWithValue("$id", nodeId);
                command.Parameters.AddWithValue("$val", value);
                command.ExecuteNonQuery();
            }
        }
        catch (Exception ex) { Console.WriteLine($"Data Lake storage failure: {ex.Message}"); }
    }

    public override void CreateAddressSpace(IDictionary<Opc.Ua.NodeId, IList<IReference>> externalReferences)
    {
        base.CreateAddressSpace(externalReferences);
        ushort nsIndex = NamespaceIndex;
        
        FolderState rootFolder = new FolderState(null) 
        { 
            NodeId = new Opc.Ua.NodeId("Substation_01", nsIndex), 
            BrowseName = new QualifiedName("Substation_01", nsIndex), 
            DisplayName = new LocalizedText("Substation_01") 
        };
        AddPredefinedNode(SystemContext, rootFolder);

        _buttonNode = new BaseDataVariableState(rootFolder) 
        { 
            NodeId = new Opc.Ua.NodeId("Substation_01.Inputs.ButtonStatus", nsIndex), 
            BrowseName = new QualifiedName("ButtonStatus", nsIndex), 
            DisplayName = new LocalizedText("ButtonStatus"), 
            DataType = DataTypeIds.String, 
            Value = "RELEASED" 
        };
        rootFolder.AddChild(_buttonNode);
        AddPredefinedNode(SystemContext, _buttonNode);

        _voltageNode = new BaseDataVariableState(rootFolder)
        {
            NodeId = new Opc.Ua.NodeId("Substation_01.Telemetry.LiveVoltage", nsIndex),
            BrowseName = new QualifiedName("LiveVoltage", nsIndex),
            DisplayName = new LocalizedText("LiveVoltage"),
            DataType = DataTypeIds.Double,
            Value = 48.0
        };
        rootFolder.AddChild(_voltageNode);
        AddPredefinedNode(SystemContext, _voltageNode);

    // --- TASK A: Build and bind our real-time AI node directly to the server folder tree ---
        _aiScoreNode = new BaseDataVariableState(rootFolder)
        {
            NodeId = new Opc.Ua.NodeId("Substation_01.AI.AnomalyScore", nsIndex),
            BrowseName = new QualifiedName("AnomalyScore", nsIndex),
            DisplayName = new LocalizedText("AnomalyScore"),
            DataType = DataTypeIds.Double,
            Value = 0.0 // Defaults to completely safe operational status score
        };
        rootFolder.AddChild(_aiScoreNode);
        AddPredefinedNode(SystemContext, _aiScoreNode);

        _pollingTimer = new Timer(PollHardware, null, 1000, 100);
        Task.Run(async () => await ConnectMqttAsync());

        _videoCts = new System.Threading.CancellationTokenSource();
        // Spawn an isolated background thread lane to manage high-frequency image allocations
        _videoCaptureTask = System.Threading.Tasks.Task.Run(
            async () => await ProcessVideoBuffersAsync(_videoCts.Token), 
            _videoCts.Token
        );
        Console.WriteLine("[IMAGE ENGINE] Background frame buffer allocation task successfully deployed.");

    }

    private void PollHardware(object? state)
    {
        try
        {
            PinValue buttonReading = _gpio.Read(_buttonPin);
            string currentStatus = buttonReading == PinValue.High ? "PRESSED" : "RELEASED";

            if (currentStatus != _lastStatus)
            {
                if (_buttonNode != null)
                {
                    _buttonNode.Value = currentStatus;
                    _buttonNode.ClearChangeMasks(SystemContext, true);

                   // CONCEPT: Log physical breadboard hardware state changes directly to local storage file
                    LogToDataLake("Substation_01.Inputs.ButtonStatus", currentStatus);
                }
                Console.WriteLine($"[EVENT CHG] Physical Pin 22 Transitioned to: {currentStatus}");
                _lastStatus = currentStatus;
            }
        }
        catch (Exception ex) { Console.WriteLine($"Hardware Error: {ex.Message}"); }
    }

    private async Task ConnectMqttAsync()
    {
        try
        {
            var clientFactory = new MqttClientFactory(); 
            _mqttClient = clientFactory.CreateMqttClient();
            var clientOptions = new MqttClientOptionsBuilder().WithTcpServer("127.0.0.1", 18830).Build();

            _mqttClient.ApplicationMessageReceivedAsync += e =>
            {
                try
                {
                    string payloadText = Encoding.UTF8.GetString(e.ApplicationMessage.Payload);
                    if (!string.IsNullOrEmpty(payloadText))
                    {
                        using JsonDocument doc = JsonDocument.Parse(payloadText);
                        JsonElement root = doc.RootElement;

                        if (root.TryGetProperty("LiveVoltage", out JsonElement voltageProp) && _voltageNode != null)
                        {
                            double extractedValue = voltageProp.GetDouble();
                            _voltageNode.Value = extractedValue; 
                            _voltageNode.ClearChangeMasks(SystemContext, true);
                            LatestLiveVoltage = (float)extractedValue;
                            GridVoltageTimeSeries.PushMetric((float)extractedValue);
                            
                            LogToDataLake("Substation_01.Telemetry.LiveVoltage", extractedValue.ToString());

                            float numericButton = _lastStatus == "PRESSED" ? 1.0f : 0.0f;
                            double calculation = RunLiveInference((float)extractedValue, numericButton);

                            if (_aiScoreNode != null)
                            {
                                _aiScoreNode.Value = calculation; 
                                _aiScoreNode.ClearChangeMasks(SystemContext, true);
                                LatestAnomalyScore = calculation;

                                // Native C# Closed-Loop Distributed Hardware Control Gate
                                if (calculation > 0.0)
                                {
                                    Console.WriteLine($"[🚨 SYSTEM TRIP] Outlier Caught! Voltage: {extractedValue}V. COMMMANDING REMOTE ARDUINO PINS!");
                                    
                                    if (_arduinoGpio != null && _arduinoGpio.IsPinOpen(_greenLedPin) && _arduinoGpio.IsPinOpen(_redLedPin))
                                    {    
                                        _arduinoGpio.Write(_greenLedPin, System.Device.Gpio.PinValue.Low);  // Kill Secure LED
                                        _arduinoGpio.Write(_redLedPin, System.Device.Gpio.PinValue.High); // Fire Emergency LED
                                    }
                                }
                                else
                                {
                                    if (_arduinoGpio != null && _arduinoGpio.IsPinOpen(_greenLedPin) && _arduinoGpio.IsPinOpen(_redLedPin))
                                    {
                                        _arduinoGpio.Write(_greenLedPin, System.Device.Gpio.PinValue.High); // Keep Secure LED Active
                                        _arduinoGpio.Write(_redLedPin, System.Device.Gpio.PinValue.Low);   // Keep Emergency LED Dormant
                                    }
                                }
                            }
                                        // --- WEBSOCKET REAL-TIME DATA TRANSMISSION ---
                            var syncPayload = new
                            {
                                StreamType = "TELEMETRY_NUMBERS_FRAME",
                                LiveVoltage = extractedValue,
                                ButtonStatus = _lastStatus,
                                AnomalyScore = calculation,
                                OperatorStatus = calculation > 0 ? "ALERT TRIGGERED" : "AUTHORIZED ENGINEER"
                            };

                            string jsonString = JsonSerializer.Serialize(syncPayload);
                            var bytes = Encoding.UTF8.GetBytes(jsonString);
                            var arraySegment = new ArraySegment<byte>(bytes);

                            lock (_lockObject)
                            {
                                foreach (var socket in _activeWebSockets)
                                {
                                    if (socket.State == WebSocketState.Open)
                                    {
                                        _ = socket.SendAsync(arraySegment, WebSocketMessageType.Text, true, CancellationToken.None);
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) 
                { 
                    Console.WriteLine($"Bridge processing exception: {ex.Message}"); 
                }
                return Task.CompletedTask;
            };

            await _mqttClient.ConnectAsync(clientOptions, CancellationToken.None);
            var subscribeOptions = clientFactory.CreateSubscribeOptionsBuilder().WithTopicFilter(f => f.WithTopic("us/energy/substation1/battery")).Build();
            await _mqttClient.SubscribeAsync(subscribeOptions, CancellationToken.None);
            Console.WriteLine("[Bridge Process] Gateway is live and awaiting metrics injection strings.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Bridge loop interface connection crash: {ex.Message}");
        }
    }

    private async System.Threading.Tasks.Task ProcessVideoBuffersAsync(System.Threading.CancellationToken token)
    {
        Console.WriteLine("[IMAGE ENGINE] Initializing unmanaged video hardware buffer interface on /dev/video0...");
        
        // Pre-allocate our contiguous flat 4D array memory footprint matching: [1, Channel, Height, Width]
        // 1 frame x 3 color channels (RGB) x 224px high x 224px wide = 150,528 float slots
        float[] tensorMemoryBuffer = new float[1 * 3 * _targetHeight * _targetWidth];
        int channelStride = _targetHeight * _targetWidth; // Exactly 50,176 elements per color layer

        // Allocate our raw interleaved [R,G,B,R,G,B] byte block canvas matching our dimension constraints
        byte[] rawFrameBuffer = new byte[_targetWidth * _targetHeight * 3];

        while (!token.IsCancellationRequested)
        {
            try
            {
                // 1. BASIC-FUNDAMENTAL TRACK: Raw Linux V4L2 Hardware Frame Grabber Pass
                // We call the native Linux fswebcam utility tool to execute an optimized, low-level
                // hardware capture pass directly from /dev/video0, freezing a single frame buffer snapshot.
                using (var process = new System.Diagnostics.Process())
                {
                    process.StartInfo.FileName = "fswebcam";
                    process.StartInfo.Arguments = "-r 640x480 --no-banner -q /app/live_capture.jpg";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    
                    // Allow the unmanaged hardware driver threads up to 500ms to snap and write the matrix data frames
                    await process.WaitForExitAsync(token);
                }

                // Verify the file was captured successfully before executing memory transformations
                string captureFilePath = "/app/live_capture.jpg";
                if (!System.IO.File.Exists(captureFilePath))
                {
                    await System.Threading.Tasks.Task.Delay(100, token);
                    continue;
                }

                // 1. BASIC-FUNDAMENTAL TRACK: Raw Hardware Linux File Ingestion
                // We use our open-source ImageSharp assembly to intercept the live pixel data 
                // streaming out of the /dev/video0 USB file descriptor pathway.
                using (var cameraFrameImage = SixLabors.ImageSharp.Image.Load<SixLabors.ImageSharp.PixelFormats.Rgb24>(captureFilePath))
                {
                    // Dynamically downsample the raw 720p hardware canvas down to our model constraints
                    cameraFrameImage.Mutate(context => context.Resize(_targetWidth, _targetHeight));

                    // Extract the unmanaged pixel array bytes straight out of the heap into our buffer
                    cameraFrameImage.CopyPixelDataTo(rawFrameBuffer);

                    using (var memoryStream = new System.IO.MemoryStream())
                    {
                        cameraFrameImage.SaveAsJpeg(memoryStream);
                        byte[] imageBytes = memoryStream.ToArray();
                        string base64ImageString = System.Convert.ToBase64String(imageBytes);
                        LatestBase64Image = $"data:image/jpeg;base64,{base64ImageString}";

                        var liveImagePayload = new
                        {
                            StreamType = "LIVE_IMAGE_FRAME", // Specialized image tag
                            ImageData = $"data:image/jpeg;base64,{base64ImageString}"
                        };

                        string jsonPayload = System.Text.Json.JsonSerializer.Serialize(liveImagePayload);
                        byte[] networkBytes = System.Text.Encoding.UTF8.GetBytes(jsonPayload);
                        var arraySegment = new System.ArraySegment<byte>(networkBytes);

                        lock (_lockObject)
                        {
                            foreach (var socket in _activeWebSockets)
                            {
                                if (socket.State == WebSocketState.Open)
                                {
                                    _ = socket.SendAsync(arraySegment, WebSocketMessageType.Text, true, CancellationToken.None);
                                }
                            }
                        }
                    }
                }

                // 2. ADVANCED-PRODUCTION TRACK: High-Performance Planar Tensor Reshaping Matrix
                // Loop through our raw byte buffer array and execute our flat math stride jumps
                for (int y = 0; y < _targetHeight; y++)
                {
                    for (int x = 0; x < _targetWidth; x++)
                    {
                        // Calculate where this pixel sits inside our flat 1D interleaved hardware byte line
                        int rawByteOffset = ((y * _targetWidth) + x) * 3;
                        int linearPixelPosition = (y * _targetWidth) + x;

                        // Grab the raw 0-255 bytes, cast them to floats, and scale them to a normalized 0.0f-1.0f range
                        // Shuffle them into isolated, back-to-back planar layers to eliminate format noise
                        tensorMemoryBuffer[0 + linearPixelPosition] = rawFrameBuffer[rawByteOffset] / 255.0f;               // Red Plane
                        tensorMemoryBuffer[channelStride + linearPixelPosition] = rawFrameBuffer[rawByteOffset + 1] / 255.0f;   // Green Plane
                        tensorMemoryBuffer[(channelStride * 2) + linearPixelPosition] = rawFrameBuffer[rawByteOffset + 2] / 255.0f; // Blue Plane
                    }
                }

                // Wrap the flat float array block inside a standardized Microsoft DenseTensor layout descriptor
                var dimensions = new int[] { 1, 3, _targetHeight, _targetWidth };
                var activeInputTensor = new Microsoft.ML.OnnxRuntime.Tensors.DenseTensor<float>(tensorMemoryBuffer, dimensions);

                // 3. CYBERSECURITY / SOC IMAGE INTEGRITY TAMPER PROTECTION
                // An unvarying flat signal (all zeros) indicates an optical block or camera disruption event.
                if (tensorMemoryBuffer[0] == 0.0f && tensorMemoryBuffer[channelStride] == 0.0f && tensorMemoryBuffer[channelStride * 2] == 0.0f)
                {
                    Console.WriteLine("[🚨 INDUSTRIAL SOC ALERT] CRITICAL: Camera lens blackout or hardware stream tamper detected!");
                }

                // Throttle video ingestion rate to 10 frames per second to preserve edge CPU processing thresholds
                await System.Threading.Tasks.Task.Delay(100, token);
            }
            catch (System.OperationCanceledException) { break; }
            catch (System.Exception ex)
            {
                Console.WriteLine($"[IMAGE ERROR] Memory allocation drop or camera device path timeout: {ex.Message}");
                await System.Threading.Tasks.Task.Delay(1000, token); // Backoff for 1 second before re-binding to let the bus settle
            }
        }
    }    
}

public class SCADABinaryTransmissionService : PiOPCUABridge.Protos.ScadaTransmissionEngine.ScadaTransmissionEngineBase
{
    // Override the auto-generated base method contract we declared in our .proto file
    public override System.Threading.Tasks.Task<PiOPCUABridge.Protos.StreamAckResponse> StreamTelemetryNode(
        PiOPCUABridge.Protos.TelemetryDataPacket request, 
        Grpc.Core.ServerCallContext context)
    {
        // PHYSICALLY PRINT THE INBOUND BINARY PAYLOAD VARIABLES
        System.Console.WriteLine($"[🛰️ BINARY gRPC INGEST] Packets intercepted! Volts: {request.LiveVoltage}V | AI: {request.AnomalyScore} | OP: {request.OperatorStatus}");

        // Construct and return a packed binary verification acknowledgement
        return System.Threading.Tasks.Task.FromResult(new PiOPCUABridge.Protos.StreamAckResponse
        {
            Success = true,
            ConfirmationMsg = "Binary data payload safely stored in edge node RAM."
        });
    }
}

public class ScadaGraphData
{
    public float LiveVoltage { get; set; }
    public double AnomalyScore { get; set; }
    public string OperatorStatus { get; set; } = string.Empty;
    public string ButtonStatus { get; set; } = string.Empty;
    public string ImageData { get; set; } = string.Empty; // Holds your massive camera string 
}

public class SCADAGraphQueryResolver
{
    public ScadaGraphData GetSystemMetrics()
    {
        // 1. Fetch current live variables from your master SCADA execution thread variables
        // (Assuming _lastCalculatedVoltage, _currentAnomalyScore, etc., map to your active loops)
        float currentVolts = CustomNodeManager.LatestLiveVoltage;
        double currentAnomaly = CustomNodeManager.LatestAnomalyScore;
        
        // 2. Return the data tightly mapped to your GraphQL object graph schema
        return new ScadaGraphData
        {
            LiveVoltage = currentVolts,
            AnomalyScore = currentAnomaly,
            OperatorStatus = currentAnomaly > 0.5 ? "ANOMALY TRIP ACTIVATED" : "SYSTEM AUTHORIZED",
            ButtonStatus = "NOMINAL",
            // This is the heavy variable that will sit completely idle in memory 
            // until a client explicitly asks for it by name!
            ImageData = CustomNodeManager.LatestBase64Image
        };
    }
}

public class SCADATimeSeriesRingBuffer
{
    private readonly float[] _bufferPool;
    private readonly int _capacityBoundary;
    private int _headPointerIndex = 0;
    private int _currentTotalCount = 0;
    private readonly object _threadLockGate = new object();

    public SCADATimeSeriesRingBuffer(int capacity)
    {
        _capacityBoundary = capacity;
        _bufferPool = new float[capacity]; // Allocate the exact memory array footprint once!
    }

    // Thread-safe method to slide a fresh metric into the rolling ring
    public void PushMetric(float newValue)
    {
        lock (_threadLockGate)
        {
            _bufferPool[_headPointerIndex] = newValue;
            
            // Advance the pointer or wrap it back to 0 if it hits the capacity edge
            _headPointerIndex = (_headPointerIndex + 1) % _capacityBoundary;
            
            if (_currentTotalCount < _capacityBoundary)
            {
                _currentTotalCount++;
            }
        }
    }

    // Extracts the entire 50-value historical sequence matrix ordered oldest-to-newest
    public float[] GetHistoricalSequenceMatrix()
    {
        lock (_threadLockGate)
        {
            float[] orderedResultMatrix = new float[_currentTotalCount];
            
            // Calculate where the oldest data point currently sits in the circular memory lane
            int startOffsetIndex = _currentTotalCount < _capacityBoundary ? 0 : _headPointerIndex;

            for (int i = 0; i < _currentTotalCount; i++)
            {
                int targetCalculatedIndex = (startOffsetIndex + i) % _capacityBoundary;
                orderedResultMatrix[i] = _bufferPool[targetCalculatedIndex];
            }

            return orderedResultMatrix;
        }
    }

    public int GetCurrentCount() => _currentTotalCount;
}

