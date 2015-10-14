##  Identify what aspects of the work have been correctly implemented and what have not.
	- All parts have been implemented to the best of my ability

##  Identify anyone with whom you have collaborated or discussed the assignment.
	- N/A

##  Say approximately how many hours you have spent completing the assignment.
	- 1.5 hrs 
	- 1 hrs 
	- .5 hrs 
	- 1 hrs 
	- .5 hrs
	==========
	4.5 Hours

## Are the heuristics used in this assignment to determine incidents "even that good"?
	- The heuristics are not great, because the checks for what constitutes an 
	attack are very basic. I am only checking the bare minimum so there is likely 
	to be a lot of missed cases and also a lot of false alarms. 

## If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
	- Credit card number check can be better b/c each brand has a specific format 
	and so we can utilize known information to catch the credit car number and 
	know the provider.
	- Pattern matching for Nmap and Nikto won't work on all packets cause they don't
	always have a payload field so I would try to find other indicators of these
	scans and add that to the program.
	- Pattern matching Nmap and Nikto for the web logs can also fail since there may
	be more subtle traces of it. I would try to add more checks for the subtle cases.
	- Detecting shellcode is using regex to catch \x which may not even be shellcode
	so I would add a better regex to check for shellcode such as what is used by
	existing shellcode detection software.
	- Maybe add checks for UDP incidents if such cases exist
