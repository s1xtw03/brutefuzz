# brutefuzz

brutefuzz is a program for attacking services using a packet 
capture as a template. it helps inject fuzzy strings via 
four different modes, and offers varying levels of verbosity.

* R - replay mode replays a packet or set of packets at a service
* I - insert mode overwrites a set of bytes with a specified value at a specified index into the packet data
* B - brute force mode inserts a list of strings at each position in a packet
* S - search mode finds and replaces an existing string with a given string, based on a regular expression.