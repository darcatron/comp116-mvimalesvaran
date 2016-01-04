# Sniffer
This sniffer is a python script that can be used to display potentially sensitive data that is sent over the internet in plain-text. It utilizes Scapy to sniff the user's network packets and runs heuristics on the content. Any sensitive data found will be printed for the user's review. Sniffed packets are not saved to memory so the script can be run continuously.

# Usage
To run the program:
```py
python sniffer.py
```

By default the program dismisses alerts on sensitive numerical data (credit cards, social security, etc.) as there are many false positives. These alerts can be turned on with the "-n" argument:
```py
python sniffer.py -n
```