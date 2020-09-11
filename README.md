# brutefuzz

brutefuzz is a program for attacking services using a packet 
capture as a template. it helps inject fuzzy strings via 
four different modes, and offers varying levels of verbosity.

this is most useful for assessing how custom protocols and services
handle unexpected data.

* R - replay mode replays a packet or set of packets at a service
* I - insert mode overwrites a set of bytes with a specified value at a specified index into the packet data
* B - brute force mode inserts a list of strings at each position in a packet
* S - search mode finds and replaces an existing string with a given string, based on a regular expression.

To demonstrate, the following will brute force a string across an HTTP GET request to Python's simple HTTP server:

1. Capture HTTP traffic to a pcap file. For this example, I'm using the [WireShark Sample Capture](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap). 
2. Deploy an HTTP server: `# python -m http.server 80`
3. Run brutefuzz, targeting your HTTP server IP and port. Below demonstrates full verbosity, fuzzing the string `hello`:

~~~
# ./brutefuzz.py -p ~/Downloads/http.cap -vvv -m B -f fuzz -t 127.0.0.1 
2020-09-10 23:16:59,891 Skipping packet, probably it had no data.
2020-09-10 23:16:59,891 Skipping packet, probably it had no data.
2020-09-10 23:16:59,891 Skipping packet, probably it had no data.
2020-09-10 23:16:59,891 ~~~~!Testing Packet: 4!~~~~


2020-09-10 23:16:59,892 Fuzz string: hello

2020-09-10 23:17:02,897 Not seeing a banner: 127.0.0.1:80
2020-09-10 23:17:03,902 
0000   68 65 6C 6C 6F 64 6F 77  6E 6C 6F 61 64 2E 68 74   hellodownload.ht
0010   6D 6C 20 48 54 54 50 2F  31 2E 31 0D 0A 48 6F 73   ml HTTP/1.1..Hos
0020   74 3A 20 77 77 77 2E 65  74 68 65 72 65 61 6C 2E   t: www.ethereal.
0030   63 6F 6D 0D 0A 55 73 65  72 2D 41 67 65 6E 74 3A   com..User-Agent:
0040   20 4D 6F 7A 69 6C 6C 61  2F 35 2E 30 20 28 57 69    Mozilla/5.0 (Wi
0050   6E 64 6F 77 73 3B 20 55  3B 20 57 69 6E 64 6F 77   ndows; U; Window
0060   73 20 4E 54 20 35 2E 31  3B 20 65 6E 2D 55 53 3B   s NT 5.1; en-US;
{truncated}
2020-09-10 23:17:03,905 127.0.0.1:80 responded to your message with the following: 
2020-09-10 23:17:03,907 
0000   3C 21 44 4F 43 54 59 50  45 20 48 54 4D 4C 20 50   <!DOCTYPE HTML P
0010   55 42 4C 49 43 20 22 2D  2F 2F 57 33 43 2F 2F 44   UBLIC "-//W3C//D
0020   54 44 20 48 54 4D 4C 20  34 2E 30 31 2F 2F 45 4E   TD HTML 4.01//EN
0030   22 0A 20 20 20 20 20 20  20 20 22 68 74 74 70 3A   ".        "http:
0040   2F 2F 77 77 77 2E 77 33  2E 6F 72 67 2F 54 52 2F   //www.w3.org/TR/
{truncated}
2020-09-10 23:17:06,913 Not seeing a banner: 127.0.0.1:80
2020-09-10 23:17:07,916 Outbound data: 
2020-09-10 23:17:07,918 
0000   47 68 65 6C 6C 6F 6F 77  6E 6C 6F 61 64 2E 68 74   Ghelloownload.ht
0010   6D 6C 20 48 54 54 50 2F  31 2E 31 0D 0A 48 6F 73   ml HTTP/1.1..Hos
0020   74 3A 20 77 77 77 2E 65  74 68 65 72 65 61 6C 2E   t: www.ethereal.
0030   63 6F 6D 0D 0A 55 73 65  72 2D 41 67 65 6E 74 3A   com..User-Agent:
{truncated}
2020-09-10 23:17:07,919 127.0.0.1:80 responded to your message with the following: 
2020-09-10 23:17:07,922 
0000   3C 21 44 4F 43 54 59 50  45 20 48 54 4D 4C 20 50   <!DOCTYPE HTML P
0010   55 42 4C 49 43 20 22 2D  2F 2F 57 33 43 2F 2F 44   UBLIC "-//W3C//D
0020   54 44 20 48 54 4D 4C 20  34 2E 30 31 2F 2F 45 4E   TD HTML 4.01//EN
{truncated}
2020-09-10 23:23:02,145 Not seeing a banner: 127.0.0.1:80
2020-09-10 23:23:03,147 Outbound data: 
2020-09-10 23:23:03,151 
0000   47 45 68 65 6C 6C 6F 77  6E 6C 6F 61 64 2E 68 74   GEhellownload.ht
0010   6D 6C 20 48 54 54 50 2F  31 2E 31 0D 0A 48 6F 73   ml HTTP/1.1..Hos
0020   74 3A 20 77 77 77 2E 65  74 68 65 72 65 61 6C 2E   t: www.ethereal.
{truncated}
...
2020-09-10 23:23:10,172 Not seeing a banner: 127.0.0.1:80
2020-09-10 23:23:11,174 Outbound data: 
2020-09-10 23:23:11,177 
0000   47 45 54 20 68 65 6C 6C  6F 6C 6F 61 64 2E 68 74   GET helloload.ht
0010   6D 6C 20 48 54 54 50 2F  31 2E 31 0D 0A 48 6F 73   ml HTTP/1.1..Hos
0020   74 3A 20 77 77 77 2E 65  74 68 65 72 65 61 6C 2E   t: www.ethereal.
0030   63 6F 6D 0D 0A 55 73 65  72 2D 41 67 65 6E 74 3A   com..User-Agent:
~~~