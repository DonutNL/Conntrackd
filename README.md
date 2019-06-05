Conntrackd is an idea by Chris Gralike to create a Web managable L2 access gateway to cloud environments where logging and connection handling is simplified for end-users.

This project itends to:

  - Provide a NAT gateway using firewalld / iptables;
  - Provide logging of active connections being utilized;
  - Provide notifications when NAT entries are utilized;
  - Provide means to actively kill connections;
  - Provide a stand-alone web interface to moderate the NAT;
  - Provide means to instruct capture and handle inbound/outbound auto-ssh tunneling (future);
  - Use as much native linux functionality as possible;
  - Keep the solution as simple as possible;
  - Make the solution as secure as possible.
  
  
  Architecture
  
  
 [ WebGate       ]
 [0. REST webgate ]  <------------------------------------------------------------|
         |                                                                        |
         |                                                                        |
         |                                                                        |
         |                                                                        |
 [   Secure DMZ  ]              [ Access Segment   ]                    [ Remote clients / IOT Clouds   ]
 [1. mgmt node (SQL)]  <------- [2. Linux NAT node ]    <-------        [3. Inbound auto SSH requests   ]
                                   |
                                   |
                             [ Maintanance / LCM etc    ]
                             [ 4. CICD tooling          ]
                             
1. Mgmt node
contains all the configuration data and collects alle the logging. The Linux NAT node either pulls the configuration from the mgmt node or the mgmt node pushes the configuration to the Linux NAT node. The NAT node will either create NAT entries toward enviroments when Site2Site VPN is used or will accept handle inbound SSH requests from known nodes. For acceptance and NAT iptables/firewalld will be used;

3. Remote clients will register with a designated Webgate and will then periodically poll for its configuration and further instructions. Registered clients can be configured using the mgmt node. This node will push its configuration into a stand alone webgate. Configuration includes certificates, source IP remote client, dest IP for NAT node, if a connection is required and when the connection is required. When the configuration is received it is executed on the remote client. The Webgate and an certificate for encryption are preinstalled and will not be exchanged. Using this encryption the pcert for auto ssh is exchanged. Access from the webgate into different networks should be prevented and the security of the webgate should be maximized.

2. The natserver will query the mgmt node for its configuration and will push its conntrack logging periodically to the mgmt node. It will continuesly inform the mgmt server about active connections, active sessions tha allow mgmt to actively log, notify, kill these connections. The NAT server will provide the a L2 gateway for CICD tooling and databases to collect data from remote IOT sites. 
                          
