<!DOCTYPE html>
<html>
<head>
</head>
<body>

<h1>SimplePacketSniffer</h1>

<h2>Description</h2>

<p>The <strong>SimplePacketSniffer</strong> script operates as a packet sniffer, intercepting network traffic to analyze HTTP requests for potential sensitive information, such as usernames and passwords.</p>

<p>When a packet containing an HTTP request is captured, the script inspects the request for specific keywords commonly associated with login credentials, such as "login," "username," "password," and variations thereof. These keywords are predefined in the script.</p>

<p>Upon identifying a potential match, the script prints out the raw data associated with the packet, which may include the username and password fields if they are transmitted in plaintext. This process simulates the method used by malicious actors to sniff for and extract sensitive information from network traffic.</p>

<h2>Usage</h2>

<ol>
  <li>Ensure you have Python installed on your system.</li>
  <li>Install the required dependencies by running <code>pip install scapy</code>.</li>
  <li>Run the script with the desired network interface specified using the <code>--interface</code> flag.</li>
</ol>

<p><strong>Example:</strong></p>

<pre><code>python sniffer.py --interface eth0</code></pre>

<h2>Prerequisites</h2>

<p>To use this script, the user must have access to the target network traffic. This could involve gaining access through methods such as Man-in-the-Middle (MITM) attacks or other means of intercepting network traffic.</p>

<h2>Disclaimer</h2>

<p>This script is provided for educational purposes only. Do not use it for unauthorized access to information or for any illegal activities. Always ensure you have proper authorization before monitoring network traffic.</p>

</body>
</html>
