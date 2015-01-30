# DAC
# Author: Paul Patras

DAC is a Linux application that implements a decentralised adaptive algorithm, which can be 
deployed on commodity Wi-Fi stations to optimise the throughput performance of WLANs based
on the IEEE 802.11 technology.

DAC targets the best-effort (BE) access category and was developed in conjunction with a 
modified version of the popular Madwifi driver, whereby the update of the contention parameters 
assigned to the BE access category, as well as local WME configuration was enabled. 
The modified driver is available at:

https://github.com/paulpatras/madwifi-distributed

Details about DAC's operation are documented in the flowing research papers:

- P. Patras, A. Banchs, P. Serrano, A. Azcorra, "A Control Theoretic Approach to Distributed 
Optimal Configuration of 802.11 WLANs", IEEE Transactions on Mobile Computing, vol. 10, no. 6, 
pp. 897–910, Jun. 2011.
- P. Serrano, P. Patras, A. Mannocci, V. Mancuso, A. Banchs, "Control Theoretic Optimization 
of 802.11 WLANs: Implementation and Experimental Evaluation", Computer Networks, vol. 57, 
no. 1, pp. 258–272, Jan. 2013.
