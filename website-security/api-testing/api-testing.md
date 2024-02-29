# API Testing

## Explanation & Exploitation

Application Programming Interfaces (API) is code that serves as a set of rules / protocols that allow one software application to interact with another. This allows for the exchange of data between different systems. Apart from that, APIs also modularises code for users to perform functions. For example, registering users can happen through sending POST requests to `/api/user/register`. 

All dynamic websites are composed of APIs retrieving and storing data for users. Representational State Transfer (REST) APIs is a set of architectural principles for designing APIs, and are often used for websites. 

Generally, when doing API testing, one should fuzz the API endpoint (such as `/api`) to find out all the possible endpoints. This can be done using tools like `gobuster`. Each application is different, so they utilise different APIs. As such, doing proper enumeration is key to finding vulnerabilities.

After finding the endpoints, try to find any documentation for the functions provided. One can test the APIs, sending POST or GET requests with varying parameters and discover attack surfaces. 

In my opinion, API testing involves a lot of blackbox 'guesswork' (unless we have the source code). It is especially difficult with custom APIs, so my methodology normally boils down to:

1. Find as many endpoints to expand attack surface.
2. Send random requests with random parameters to each of these endpoints (if there aren't too many), see responses. See what works and what doesn't.
3. With the functions that are deemed as 'suspicious', try to send funny parameters and see what happens.

In my experience doing CTFs, a wide range of vulnerabilities can be exploited via APIs, such as SQL Injection by passing unsanitised queries, prototype pollution by adding properties or even command injection. 