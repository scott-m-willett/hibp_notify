# Author: Scott Willett
# Version: 01/07/2019
#
# Description: 	Loop through a list of email addresses. 
# 				For each breach found for that email address at haveibeenpwned.com, 
# 				notify someone once about the breach via email.
#
#				Can be useful to run this daily in your environment and send email notifications through to a ticket system.
#
#				Please change the variables in the VARIABLES section.

import http.client
import time
import json
import re
import smtplib
from email.message import EmailMessage

### VARIABLES ###

# A list of users to check - see if they've been pwned. First column should be an email. Needs to be a second column seperated by a ',' char currently
users_csv = './staff.csv'

# Where the breaches file exists. Matches emails to breaches (basically to track if this has been discovered before)
breaches_file = './breaches.txt'

# A file containing a email canned response when a notification is found.
email_template_file = './email_template.txt'

# With regards to the email notification, specify below who you want the email to be from, and where to send it to
email_from = ""
email_to = ""

# An smtp server to send a notification email about pwned accounts
smtp_server = ''
smtp_login_email = ''
smtp_login_pass = ''

### END VARIABLES ###

# Send an email to notify someone of the breach, using the 
def email_notify(email, breach):
    subject = "Pwned Account: " + email + " (" + breach + ")"
    template_file = open(email_template_file)	
    template = template_file.read()
    altered = re.sub("{email}", email, template)
    altered = re.sub("{breach}", breach, altered)
    content = altered
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = email_from 	
    message['To'] = email_to	
    message.set_content(content)
    smtp = smtplib.SMTP(smtp_server)						
    smtp.login(smtp_login_email,smtp_login_pass) 	
    smtp.send_message(message)
    smtp.quit()

# User agent required as per api doco
headers = {'user-agent':'python-script - http.client'}

# The domain of the api
domain = 'haveibeenpwned.com'

# Load a list of emails and associated breaches
breaches_file = open(breaches_file,'r')
breaches_list = breaches_file.read()
breaches_file.close()

# Load a list of staff from a csv file, split it into an array for each line (\n)
file = open(users_csv,'r')	
users = file.read()
users = users.split("\n")		

# Loop through the users
for line in users:
    time.sleep(2)                    # Required so as to now abuse the api service (rate limited by 1.5 seconds each request)
    email = line.split(',')[0]        # First column should be the email address 
    api_url = ('/api/v2/breachedaccount/%s?truncateResponse=true' % (email))    # api call for the user
    connection = http.client.HTTPSConnection(domain)                            # The https connection object
    connection.request('GET', 'https://' + domain + api_url,'',headers)            # The request to be made on the connection object
    response = connection.getresponse()                                            # The actual request
    status = response.status                                                       # Status of the response
    if status == 200:                          # HTTP status 200 is returned if a breach is found
        content = response.read()              # Read the response (raw json)
        breaches = json.loads(content)         # Make the raw json a python array / hash
        for breach in breaches:                # Go through each breach found
            breach_match_string = '%s:%s\n' % (email, breach['Name'])        # A string used to write to the breaches_file, or match a string in that file
            breach_match = re.search(breach_match_string, breaches_list)     # Attempt to find if the email:breach has already been discovered
            if not breach_match:                    # If not already discovered (ie: in the breaches_file/list)
                # Send a notification email
                email_notify(email,breach['Name'])
                # Write the breach to the breaches_file
                breaches_file = open(breaches_file,'a')
                breaches_file.write(breach_match_string)
                breaches_file.close()