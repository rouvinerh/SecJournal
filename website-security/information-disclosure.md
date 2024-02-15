# Information Disclosure

## Explanation

Information disclosure is when a website unintentionally reveals sensitive information, such as information about its users, or details about the backend such as the version of a database running.

These vulnerabilities arise due to reasons like:
* Forgetting to remove internal content from public content.
* Insecure configuration, such as leaving debug / verbose logging options enabled, causing errors to be printed to the screen.

Generally, I don't view this as a 'vulnerability', but more of something one can find through fuzzing and checking parts of the website. For example, running a directory scan might yield some hidden directories containing sensitive information. When testing a website, one should aim to find out as much as possible anyway via automated or manual methods.

Files like `robots.txt` can contain sensitive information, or sometimes developer comments are left behind. Sometimes, logic flaws can cause this since users may bypass access controls to view sensitive information of other users. All of these fall under the broad topic of 'information disclosure'. 

As long as you find something that helps you learn more about a website and its backend I suppose. 