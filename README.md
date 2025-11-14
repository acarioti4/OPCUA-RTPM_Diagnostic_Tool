About the Project:

The RTPM Service (Client) connects to an OPC-UA server (opc.tcp://<hostname>:<port>).

It successfully browses and reads data — so the outbound connection works.

However, OPC-UA often also needs to push data or callbacks (e.g., subscriptions, monitored items).

Often times, due to network issues (port blocks, firewalls, etc) the OPC-UA server is unable to send capability changes to the RTPMService's listener. 

System Names:
-    System A — RTPM Service (Client)
-    System B — OPC-UA Server

Focused Gameplan:

Phase 1: Verify the Callback Path (THE KEY TEST)
Goal: Prove whether System B (OPC-UA Server) can initiate connections back to System A (RTPM Service)

    - Component 1: Callback Address Detector
        Need to answer:
        1. What IP:PORT is System A (RTPM Service) advertising for callbacks?
        2. Can System B (Kepware OPC UA Server) reach that IP:PORT?
        3. Is System A (RTPM Service) actually listening on that port?

    - Build:
        Display Client Callback Info:
            When the OPC-UA client connects, log the callback endpoint it advertises
            Show all network interfaces on System A (RTPM Service)
            Identify which interface/IP the OPC-UA client library is using on System A
        Listening Port Monitor:
            After subscription creation, detect what port(s) the OPC-UA client opens
            Use netstat to show: LISTEN state sockets
            Display: "System A client listening on x.y.z.a:54321"
        Connection Attempt Logger:
            Monitor for incoming SYN packets from System B (OPC-UA Server)
            Log any connection attempts (successful or blocked)
            Use packet capture (Npcap) or netstat-based monitoring

How to Install:
-    'npm install'
-    'npm start'

How to Build executable:
-    'npm run build'

Usage:

-    In-app help:
     - Use the Help > Keybinds menu to see available shortcuts (e.g., run probe, focus endpoint, switch theme).

-    Recommended placement:
     - Run on System A (RTPM Service / client machine) to fully validate that System B (OPC-UA Server) can reach back to System A for server→client callbacks.
     - Enter `opc.tcp://<System B (OPC-UA server) IP>:<port>` in the Endpoint field and click "Run Callback Path Probe".
     - The app will:
       1) Connect to System B (OPC-UA Server) and create a subscription (forces server→client traffic).
       2) On System A, show the local client socket info and all local network interfaces.
       3) On System A, capture this process's listening ports before/after subscription.
       4) Optionally monitor incoming SYN attempts from System B (requires Npcap for best results).

-    System B–only mode (limited):
     - You can run this app on System B (OPC-UA Server) if you cannot access System A (RTPM Service).
     - What you get:
       - OPC-UA client self-test from System B (the built-in client connects to the endpoint you specify).
       - Local interfaces and process listeners on System B (OPC-UA server host).
       - Optional SYN monitoring for inbound attempts to System B.
     - What you cannot conclusively prove from System B alone:
       - That System B can initiate new connections back to System A’s listener (the true callback path required for server→client callbacks).
       - To prove B→A callback reachability, you must either:
         a) Run this app on System A (RTPM Service) — preferred; or
         b) Provide a known reachable listener on System A and test connectivity to it from System B with appropriate tooling.

Prerequisites:
-    Windows (Electron app)
-    Node.js 18+ if running from source (`npm install`, `npm start`)
-    Optional (for SYN capture): Npcap installed; the app uses the optional `cap` module if present. Without it, it falls back to `netstat` polling.

Running from Source:
-    'npm install'
-    'npm start'

Using the Packaged Build (Windows):
-    Portable EXE: look under 'dist\OPCUA-RTPM Diagnostic Tool.exe'
-    Unpacked app: 'dist\win-unpacked\OPCUA-RTPM Diagnostic Tool.exe'

Logs:
-    Probe logs are written to the application logs folder, e.g.:
-    'C:\Users\<you>\AppData\Roaming\OPCUA-RTPM Diagnostic Tool\logs\opcua-rtpm-diagnostic-tool_YYYY-MM-DDTHH-MM.log'

Notes / Mapping to Build Items:
-    Display Client Callback Info: Implemented (shows local client socket and adapters).
-    Listening Port Monitor: Implemented (pre/post subscription listeners on System A).
-    Connection Attempt Logger: Implemented with `cap` (pcap) when available; otherwise uses `netstat` polling. Captures SYN attempts from System B and summarizes in the log/UI.
 -    Endpoint Security Check: Implemented (lists all discovered endpoints with `securityMode`, `securityPolicyUri`, user token types, and a friendly classification such as None/Legacy/Modern AES). Also shows the negotiated channel’s mode/policy and a short server certificate summary when connected.
