Project 1: Phishing Email Analysis
Date: November 9, 2026

Goal
Determine whether a suspicious email in my spam folder was malicious.

Tools
Gmail “Show original” (email headers), VirusTotal

Summary
The email claimed to be from Kraken (a cryptocurrency exchange) and told me I had an unclaimed balance of $74,578. It was actually sent through a hijacked contact form on a Japanese WordPress website and contained a link to a phishing page.

Steps Taken
Reviewed the email content, analyzed the full headers using “Show original,” checked the link reputation in VirusTotal without visiting it, and reported the email as phishing.

Findings

Contact form abuse: the attacker entered my email address into a Japanese website’s contact form and wrote the scam in the message field. The site then automatically sent the message to me.
Headers confirmed this: the email was sent by PHPMailer (used by WordPress), had an unfilled “[your-subject]” placeholder in the subject, and its Reply-To pointed to the website owner, not Kraken.
SPF and DMARC passed because the email really came from the website’s own server. Authentication passing does not mean an email is safe.
Social engineering: fake large balance (greed), “inactive for 12 months” (urgency), fake reference number, a bot-generated gibberish name, and grammar mistakes (“We asks you”).
Malicious link: the link pointed to graph.org, a free anonymous publishing service, not Kraken’s website. VirusTotal: 11 vendors flagged it as malicious or phishing, and 2 as suspicious. The page was still live at the time of analysis.

Indicators of Compromise (IOCs)

Sender: wordpress@ichi-shimoichi[.]com
Sending server IP: 118.27.125[.]85
Malicious URL: hxxps://graph[.]org/NSM-423740-10-25?lisul24
Date received: November 8, 2026

Conclusion
Confirmed phishing email. The goal was to lure the victim to a fake page to steal crypto login details or money.

Recommended Actions
Do not click the link. Report the email as phishing and delete it.

What I Learned
Attackers can abuse legitimate websites to send phishing that passes email authentication checks, so the content and links must always be checked, not just SPF/DKIM/DMARC.

Screenshots
<img width="600" height="752" alt="Screenshot 2026-11-09 190437" src="https://github.com/user-attachments/assets/8b19fd42-b022-4338-b04b-f7e9d19a14f8" />
<img width="553" height="278" alt="Screenshot 2026-11-09 190445" src="https://github.com/user-attachments/assets/67fbda85-c708-4bf3-bfc3-f70d08df8080" />
<img width="797" height="561" alt="Screenshot 2026-11-09 190706" src="https://github.com/user-attachments/assets/c6abe383-51f8-455f-83e1-e61257c21fa1" />
<img width="958" height="926" alt="Screenshot 2026-11-09 190942" src="https://github.com/user-attachments/assets/d8cde620-3879-4a25-a328-0b0ceb7c4035" />

