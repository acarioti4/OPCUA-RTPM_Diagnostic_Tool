About the Project:

The RTPM Service (Client) connects to Kepware OPC UA Server (opc.tcp://<hostname>:<port>).

It successfully browses and reads data — so the outbound connection works.

However, OPC UA often also needs to push data or callbacks (e.g., subscriptions, monitored items).

Often times, due to network issues (port blocks, firewalls, etc) the Kepware OPC UA Server is unable to send capbility changes to the RTPMService's listener. 

Focused Gameplan:

Phase 1: Verify the Callback Path (THE KEY TEST)
Goal: Prove whether System B can initiate connections back to System A

    - Component 1: Callback Address Detector
        Need to answer:
        1. What IP:PORT is System A advertising for callbacks?
        2. Can System B reach that IP:PORT?
        3. Is System A actually listening on that port?

    - Build:
        Display Client Callback Info:
            When OPC UA client connects, log the callback endpoint it advertises
            Show all network interfaces on System A
            Identify which interface/IP the OPC UA client library is using
        Listening Port Monitor:
            After subscription creation, detect what port(s) the OPC UA client opens
            Use netstat/ss to show: LISTEN state sockets
            Display: "Client listening on x.y.z.a:54321"
        Connection Attempt Logger:
            Monitor for incoming SYN packets from System B
            Log any connection attempts (successful or blocked)
            Use tcpdump/Wireshark or raw socket monitoring
