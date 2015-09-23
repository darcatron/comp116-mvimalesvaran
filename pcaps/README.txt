set1.pcap

1. How many packets are there in this set?
    - 861
2. What protocol was used to transfer files from PC to server?
    - FTP
3. Briefly describe why the protocol used to transfer the files is insecure?
    - FTP does not encrypt its data and sends it in plain text
4. What is the secure alternative to the protocol used to transfer files?
    - SFTP
5. What is the IP address of the server?
    - 192.168.99.130
6. What was the username and password used to access the server?
    - USER: defcon PASS: m1ngisablowhard
7. How many files were transferred from PC to server?
    - 6
8. What are the names of the files transferred from PC to server?
    - CDkv69qUsAAq8zN.jpg
    - CJoWmoOUkAAAYpx.jpg
    - CKBXgmOWcAAtc4u.jpg
    - CLu-m0MWoAAgjkr.jpg
    - CNsAEaYUYAARuaj.jpg
    - COaqQWnU8AAwX3K.jpg

9. Extract all the files that were transferred from PC to server. These files must be part of your submission!
    - DONE

set2.pcap

10. How many packets are there in this set?
    - 77982
11. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
    - 2 (assuming genericusersync is not an account)
12. Briefly describe how you found the username-password pairs.
    - Sorted by protocol and manually looked through the info to see where logins were requested
    - Searched packets for "anon"
13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
    - IMAP, 87.120.13.118, email, 143
    - HTTP, 54.192.235.23, splunk.com, 80
14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.
    - 1

set3.pcap

15. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
    - 2 (assuming genericusersync is not an account)
16. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
    - HTTP, 162.222.171.208, forum.defcon.org, 80
    - IMAP, 210.131.4.155, email, 143
17. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.
    - 1
18. Provide a listing of all IP addresses with corresponding hosts (hostname + domain name) that are in this PCAP set. Describe your methodology.
    - 68.142.122.70 - softpedia.com
    - 64.235.154.33 - defcon23-badge-challenge.wikia.com
    - 162.222.171.208 - forum.defcon.org
    - 17.253.16.222 - a769.phobos.apple.com
    - 173.192.220.64 - tags.bluekai.com
    - 173.194.123.38 - google-analytics.com
    - 50.22.232.74 - nirsoft.net
    - 54.193.4.196 - a.wikia-beacon.com
    - 91.190.218.69 - conn.skype.com
    - I filtered wireshark to show only http and sorted it by destination. The GET request says the host and I just grabbed that.

General Questions

19. How did you verify the successful username-password pairs?
    - packet in stream said OK LOGIN OK (successful) or 403 Forbidden (failure)
20. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?
    - Use more secure protocols to send data such as HTTPS and SFTP. Also, encrypt data sent over IMAP.