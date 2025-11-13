About the Project:

The RTPM Service (Client) connects to Kepware OPC UA Server (opc.tcp://<hostname>:<port>).

It successfully browses and reads data — so the outbound connection works.

However, OPC UA often also needs to push data or callbacks (e.g., subscriptions, monitored items).

Often times, due to network issues (port blocks, firewalls, etc) the Kepware OPC UA Server is unable to send capbility changes to the RTPMService's listener. 

Goal:

I want to create a standalone executable that can be loaded onto the Kepware OPCUA Server and:
-   Auto-Detect IP Address and Listening Port for the RTPMService
-   Test and diagnose the Kepware OPC UA Server to RTPMService dataflow
-   Display whether the test succeeded or failed
-   If failed, why did it fail?
-   If failed, suggestions on how to resolve it.
-   Ideally, I would like this to be done all from the Kepware OPC UA Server without having to access the RTPMService server.