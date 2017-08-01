# Software-Defined-Networking


1) stateful_firewall.py is the main firewall program(developed from scratch) that blacklists the IP's based on counter and time thresholds. For more information, refer to the presentation attached.

2) stateless_firewall.py(modified the module that comes with POX controller to act as a stateful firewall) module can be used along with the main firewall module to block the IP's that you want to block even before the (If the malicious IP list is known beforehand)

3) learning_l2.py(developed from scratch) is the learning module is responsible for learning(discovering) the entire network

Note: stateful_firewall.py module runs along with any other compatible modules.
For more information on usage, please refer to the attached presentation.

Execution of the module:  
Run the stateful_firewall.py module along with other modules. You can use the learning_l2.py for learning the network(or any other module which is available in market) and stateless_firewall.py module(to block malicious IP's that are known beforehand) 
  
  Eg: sudo ~/pox/pox.py learning_l2 stateful_firewall stateless_firewall
 
