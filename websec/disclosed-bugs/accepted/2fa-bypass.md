# 2FA Bypass

I found a 2FA bypass on a website through a VDP, and the issue has been patched. This report has been heavily redacted at the developers' request.

## Discovery

I attempted to register as a new user on the target, and was required to enter a 2FA code to validate my email. After the correct code was entered, I was redirected to a final confirmation page, and had to click 'register' to finish the process.

This was the POST request responsible for sending the 2FA code to my email:

```http
POST /generate-otp HTTP/1.1
Host: target.com
Content-Type: application/json

{
    "email":"test@test.com"
}
```

## Exploit

The first thing I tried was to register a user with a fake email. This approach made sense since the application's functionality relied heavily on the email used during registration.

The current flow is:

1. Enter a legitimate email, which was displayed within the UI.
2. Validate email via OTP.
3. Proceed to final page to confirm registration.

To test whether the 2FA verification was robust, I entered `evil@evil.com` as the initial email.

I used BurpSuite to intercept the request in Step 2. I changed the email specified in the POST request to `/generate-otp`, replacing it with a secondary email I control. The secondary email account received the 2FA code, which was valid when entered.

To my surprise, when I was redirected to the final page, the initial email of `evil@evil.com` was unchanged, and I was able to register with a fake email. This meant that I was able to sign up as a user with **any email** without validation, and that the 2FA verification was bypassed.

Since this website's functionality relied heavily on users' emails for contacts, I was able to register and impersonate other people on the platform, which was a serious security issue.

## Remediation

When 2FA codes are sent to emails, it is important to tie the code sent to that specific email, and not just check for any valid code. It is also important for each stage of the registration process to be tied together. This prevents attackers from bypassing any steps or altering the intended flow.

This issue was reported to the developers, who acknowledged the issue and fixed it.