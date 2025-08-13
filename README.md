# Project: Phase 4 - Security Testing and Ethical and Legal Considerations

## Part A: Test Your Application
### Security Testing:
## Manual testing to simulate potential attacks:
##  A. Type of Vulnerability: SQL Injection (or NoSQL Injection, using MongoDB) 
###  Issue 1 (Login)
Testing Steps:
1. In the username or password field I entered below:
   ```
   admin' || '1'=='1'

   {"$ne": ""}

2. Then click Log-in


Affected Area: Log-in


Result: 
1. When the username is incorrect log-in fails and it goes back to home screen.
3. Even if the password is incorrect log-in goes through which is an app vulnerability
4. Unsanitized password accepted which is vulnerability.


Severity: High
- Password check is defective and risk of un-authorized log-in/access


Recommended Fix: 
1. Not awaiting the argon2.verify(...) promise, so it always returns a promise object, which is truthy.
Code should be:
  ```
    const isPasswordValid = await argon2.verify(user.hashPassword, password);
  ```

2. Validate user input. Use a validation library express-validator to ensure username and password are strings, not objects or expressions.
   
3. Prevent JSON-style NoSQL injection
Check for values like {$ne: ""} or {$gt: ""} in input before querying.



## B. Type of Vulnerability: XSS Attempt (Comments,File Name, Username)
### Issue 2 (Comment)

Testing Steps:
1. I input below as comment
   ```
   <script>alert("XSS")</script> and also <img src="x" onerror="alert('XSS')"> 
3. Click "Post" button

Affected Area: Comments area

Result:
1. The value is displayed exactly like the code below which means it was not escapped or sanitized.
   ```
   <script>alert("XSS")</script> and <img src="x" onerror="alert('XSS')">
  
  This could easily execute if rendered via dangerouslySetInnerHTML or even just inner HTML.

Severity: High
- Any user can inject malicious scripts.

- Risk of session hijacking, phishing, or defacement.

Recommended Fix:
1. Sanitize user-generated content before rendering it. Save safeComment to the database.

   Install: npm install sanitize-html

   Before saving the comment:
     ```
      import sanitizeHtml from 'sanitize-html';

      const safeComment = sanitizeHtml(commenttxt, {
         allowedTags: [], // removes all HTML
          allowedAttributes: {},
      });

3. Use DOMPurify so even if someone submits a <script> tag, it will be removed or neutralized.

   Install: npm install dompurify

   Use: 
   ```
   import DOMPurify from 'dompurify';

   <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.text) }} />

### Issue 3 (File Name)
Testing Steps:
1. Uploaded a file named:
   ```
   script>alert("XSS")</script>.docx
    
3. Click "Upload" button

Affected Area: File upload form, File list

Result: 
1. The "File Selected" label shows as
  ```
   <script>alert("XSS")</script>.docx
  ```
3. The file is uploaded and shows file name as below after uploading.
   ```
   <script>alert(%22XSS%22)<:script>.docx 

Severity: Critical
- File name displayed in the UI without proper sanitization or escaping
- This input is stored in the database and later rendered back into the DOM.
- Even if it's percent-encoded (%22 = ", etc.), some browsers or future UI updates might decode and interpret it.

Recommended Fix: 
1. Strip or replace unsafe Characters: 
  ```
   const safeFilename = req.file.originalname.replace(/[^a-zA-Z0-9_.-]/g, '_');
  ```
### Issue 4 (Username)
Testing Steps:
1. Register as new user with name and username as
  ```
   <script>alert("XSS")</script>
  ```
3. Input password and select department and role
4. Click "Register"

Result:
1. Successfully registered as
   ```
   <script>alert("XSS")</script>
   ```
   
3. I can log-in with username as
   ```
   <script>alert("XSS")</script>
   ```

Affected Area: 
- User Registeration (username and name)
- Log-in 


Severity: Critical
- Stored XSS is considered one of the most dangerous vulnerabilities
- Malicious scripts are saved in the database (persistent across sessions)
- Any page that renders username or name may unknowingly execute the script

Recommended Fix: 
1. Sanitize all user input on the server
   - npm install sanitize-html
   - Import sanitizeHtml from 'sanitize-html';
   ```
   const sanitizedUsername = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} });
   const sanitizedName = sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} });

   const newUser = new User({
      name: sanitizedName,
      username: sanitizedUsername,
    ...
   });
   - strip dangerous characters with a RegEx:
   const safeUsername = username.replace(/[<>\/'"`]/g, '');
  

## Security Audit Using npm audit

Testing steps:
1. Open the project directory in the terminal
2. Run the audit command "npm audit"
3. Since there is vulnerabilities displayed after "npm audit" attempt automatic fixes. "npm audit fix"

Express App Result:
1. npm audit - Severity: 1 high severity vulnerability
2. npm audit fix - found 0 vulnerabilities

UploadBox Result:
1. npm audit - found 0 vulnerabilities

## OWASP ZAP

Testing Steps
1. Open OWASP ZAP
2. Choose "Automated Scan"
3. In the URL to attack input : http://localhost:5173
3. Click "attack"

Result: 
1. Type: Content Security Policy (CSP) Header Not Set

   Affected Area: All pages

   Severity Risk : Medium 

   Confidence: High

   Recommended Fix: Set a proper CSP header to restrict resources the browser can load. example :
   ```
   Content-Security-Policy: default-src 'self'.
    ```
   Helps prevent XSS.
   
3. Type: Missing Anti-clickjacking Header

   Affected: All pages

   Severity Risk : Medium

   Confidence: Medium

   Recommended Fix: Set X-Frame-Options: DENY or use CSP’s frame-ancestors to prevent the site from being embedded in an iframe.
  
4. Type: Hidden File Found

   Affected Area: /.hg

   Severity: Medium

   Confidence: Low

   Recommended Fix: Remove sensitive files/directories from the deployed build or block access to them via server config
  
5. Type: X-Content-Type-Options Header Missing

   Affected Area: Static asset

   Severity: Low

   Confidence: Medium

   Recommended Fix: Add X-Content-Type-Options: nosniff header to prevent browsers from MIME-sniffing responses.

6. Type: Modern Web Application

   Affected Area: /sitemap.xml

   Severity: Informational

   Confidence: Medium

   Recommended Fix: No action needed.

## Reflection Checkpoint: 
### Why is it important to perform both manual and automated testing when evaluating the security of your application?

Performing both manual and automated security testing is important because each method uncovers different types of vulnerabilities.

- Manual testing simulates real-world attacks from the perspective of a malicious user. It’s especially helpful for detecting issues that automated tools often miss like logical flaws, injection attacks, and missing input sanitization. For example, during my testing, I discovered that I could bypass password verification using a NoSQL injection payload ({"$ne": ""}), and that fields like username, comments, and file names were all vulnerable to stored XSS attacks. These issues were only visible through hands-on testing.

- Automated testing, on the other hand, is useful for quickly identifying known vulnerabilities and configuration issues. By using tools like npm audit and OWASP ZAP, I was able to find outdated packages, missing security headers (like CSP and X-Frame-Options), and access to hidden files. These might not be immediately obvious but can be exploited in the right context.

### Key Findings:
- SQL/NoSQL Injection: I found that incorrect password inputs were still allowing log-ins due to incorrect handling of the async password check.

- XSS Vulnerabilities: I was able to input script tags in several places (comments, file names, usernames), and the data was not sanitized when rendered.

- npm audit revealed outdated packages with known vulnerabilities (fixed using npm audit fix).

- OWASP ZAP identified missing security headers and other misconfigurations that could weaken the app’s defenses.

### Fixes Implemented:

- Awaited argon2.verify() correctly to fix the password bypass issue.

- Sanitized all user input using sanitize-html, and restricted input characters with regex.

- Escaped dangerous characters in file names and usernames.

- Improved security headers to prevent clickjacking and XSS (as recommended by ZAP).

Manual testing allowed me to find critical vulnerabilities that could have easily been missed especially the XSS and NoSQL injection issues. Automated tools helped me catch misconfigurations and ensure that my dependencies were secure. By combining both approaches, I was able to gain a more complete understanding of the app’s security and take steps to make it safer for users.

## Part B: Fix Vulnerabilities
### Issue 1
   FIXES
   
   ExpressApp \routes\user.js
   
   Install: npm install express-validator
   
   Install: npm install sanitize-html

   Type: Password bypass
   
   Issue: argon2.verify(...) was not awaited
   
   Fix: await argon2.verify(...) used properly

   Type: XSS (Stored)
   
   Issue: Username and name were not sanitized before saving
   
   Fix: Used sanitize-html to strip HTML/JS

   Type: No input validation
   
   Issue: No checks to prevent object injection or invalid input
   
   Fix: Add express-validator to validate and sanitize inputs

   Validation result after the fixes:  
   
   Affected Area: Log-in
   
   Testing steps:
   
   1. In the username or password field I entered below:
      
     admin' || '1'=='1'
     {"$ne": ""}
      
   2. Then click Log-in
   
   Result: Since there is input validation (express-validator) and sanitization (sanitize-html), this input is treated as a normal string.
   
   1. When the user name is incorrect log-in fails and it goes back to home screen.
   
   2. Input admin' || '1'=='1' and {"$ne": ""} log-in fails and goes back to home screen which is expected
   
   3. Now the system validates the password correctly only allow the user to log-in when the password is correct.

### Issue 2
   FIXES
   
   ExpressApp \routes\comment.js
   
   npm install sanitize-html
   
   Type: Stored XSS
   
   Issue: User-submitted comments were saved and returned with raw HTML/JS content, allowing    <script> tags or <img onerror> payloads to be injected.
   
   Fix: Sanitize the comment txt input using sanitize-html before saving it to the database.

   UploadBox src\components\comments.jsx and src\components\CommentComposer.jsx
   
   npm install dompurify
   
   npm install sanitize-html
   
   Type: Stored XSS
   
   Issue: Accidental submission of malicious input bypassing via multiple encodings or special characters
   
   Fix: Input sanitized using sanitize-html and Output sanitized with DOMPurify
 
   Validation result after the fixes:  
   
   Testing Steps:
   
   1. I input as comment
      ```
      <script>alert("XSS")</script> and also <img src="x" onerror="alert('XSS')"> 
   2. Click "Post" button
   3. Input a normal comment "I am tall"
   4. Click "Post" button
   
   Result:
   
   1. For `<script>alert("XSS")</script> and also <img src="x" onerror="alert('XSS')">` program removes all HTML tags and attributes.
   
   2. For "I am tall" it post the exact value "I am tall"


### Issue 3
   FIXES
   
   ExpressApp \routes\file.js
   
   Type: Stored XSS via filename 
   
   Issue: Saving file originalname directly without sanitizing it.
   
   Able to upload file named : `<script>alert("XSS")</script>.docx`
   
   Fix: Sanitize filename before saving
     
      Strip unsafe characters to make the filename filesystem and UI-safe.
      // Sanitize filename by replacing disallowed characters with underscores
      const sanitizeFileName = (filename) => {
         return filename.replace(/[^a-zA-Z0-9_.-]/g, '_');
      };
   
   UploadBox src\components\FilesView.jsx and src\components\Home.jsx
   
   npm install dompurify
   
   Issue: User can upload a file with a name like <script>alert("XSS")</script>.docx, and it  is Stored in the database
   
   Fix: sanitized with DOMPurify to ensures that even if a malicious filename like `<script>alert('XSS')</script>` is passed, it will be rendered safely as text and not executed.
       
      Sanitize filename by replacing disallowed characters with underscores
      const sanitizeFileName = (filename) => {
        return filename.replace(/[^a-zA-Z0-9_.-]/g, '_');}
   
   Validation result after the fixes:  
   
   Testing Steps:
   1. Uploaded a file named: `script>alert("XSS")</script>.docx`
   2. Click "Upload" button

   Result: 
   1. The "File Selected" label replaced disallowed characters with underscores _script_alert__XSS____script_.docx
   2. The file is uploaded and replaced disallowed characters with underscores it shows file name as _script_alert__22XSS_22___script_.docx after uploading.

#### Issue 4
   FIXES
   
   Type: Input Validation
   
   Issue: Components like RegisterForm and LoginForm may accept unsafe inputs
   
   Fix: Ensure all form inputs (e.g., username, password, name) are validated and sanitized
   
   UploadBox src\components\forms\registerform.jsx and src\components\forms\LoginForm.jsx
   
   Type: Stored XSS  
   
   Issue: Saving username or name originalname directly without sanitizing it.
   
   Able to register with user name : <script>alert("XSS")</script>.docx
   
   Fix: Sanitize name and username before saving

   Steps:
   1. Register as new user with name and username as <script>alert("XSS")</script>
   2. Input password and select department and role
   3. Click "Register"
   4. Log-in using username <script>alert("XSS")</script>

   Result:
   1. Name and username are sanitized before reflecting to input field
   2. Cannot save <script>alert("XSS")</script>
   3. Log-in username is sanitized before reflecting to input field
   4. Cannot log-in with <script>alert("XSS")</script>

## Security Audit Using npm audit
Conducted a security audit of the project's dependencies using the Node.js package manager’s built-in tool:All vulnerabilities fixed after "npm audit" and "npm audit fix". This command scans the full dependency tree for known vulnerabilities based on advisories in the public npm registry. This resolved issues by updating vulnerable packages to patched versionsand replacing dependencies with secure alternatives where applicable.

## OWASP ZAP
Item 1:  Type: Content Security Policy (CSP) Header Not Set

   Affected Area: All pages

   Severity Risk : Medium 

   Confidence: High

   Recommended Fix: Set a proper CSP header to restrict resources the browser can load. example : Content-Security-Policy: default-src 'self'. Helps prevent XSS.

   Fix: npm install helmet. I added the Helmet middleware to our Express backend to set a secure CSP header:
  ```
   import helmet from 'helmet';
      app.use(helmet({
      contentSecurityPolicy: {
         directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
         }
      }
   }));
  ```

To improve security, I added a CSP header to restrict which sources the browser can load content from. This helps prevent malicious scripts from executing in the browser.

- default-src 'self' ensures that all content (scripts, styles, images, etc.) must come from own server.
- script-src 'self' specifically restricts script execution to trusted sources in this case, just own domain.
- object-src 'none' blocks potentially dangerous elements like <object>, <embed>, and <applet>, which are rarely needed and often abused.

This change aligns with modern web security best practices and significantly reduces the risk of cross-site scripting (XSS) attacks.

I tried setting the CSP using server.headers in vite.config.js, but OWASP ZAP still flagged some pages for missing headers. To fix this, I used configureServer() to add a custom middleware that sets the CSP header for every request, not just the main ones. This approach works better because it ensures the policy applies consistently across all routes and files during development.

Impact:
- Restricts scripts and content to load only from our own server
- Prevents injection of malicious external scripts
- Reduces risk of XSS attacks
- Verified in response headers and browser security checks

Item 2. Type: Missing Anti-clickjacking Header

   Affected: All pages

   Severity Risk : Medium

   Confidence: Medium

   Recommended Fix: Set X-Frame-Options: DENY or use CSP’s frame-ancestors to prevent the site from being embedded in an iframe.

  I addressed a Clickjacking security issue in ExpressApp backend. Clickjacking is when an attacker loads your site inside an invisible <iframe> on another page to trick users into clicking buttons or links without realizing it.
To prevent this, I added the following security headers using the helmet middleware:

    app.use(helmet.frameguard({ action: 'deny' }));
    This sets the X-Frame-Options: DENY header, which blocks all attempts to embed the site in an <iframe>.
    Additionally, I included this in the Content Security Policy (CSP):
    
    frameAncestors: ["'none'"]
This is a modern equivalent of the X-Frame-Options header and provides stronger protection on newer browsers.

It prevents the site from being embedded into other pages. It stops attackers from using iframe-based tricks to hijack user clicks. 

Item 3: Type: Hidden File Found

   Severity: Medium

   Confidence: Low

   Recommended Fix: Remove sensitive files/directories from the deployed build or block access to them via server config

It was found that hidden files like /.hg were publicly accessible. These files are often used by version control systems or for configuration, and exposing them can leak sensitive information like code history, internal structure, credentials, or server details.
To fix this, I added middleware in my backend (app.js) that blocks all requests targeting hidden files or directories anything starting with a dot (.)
This is a general protection approach, meaning instead of just blocking the specific /.hg path, I block access to any hidden file or folder. This is safer in the long term and helps prevent future leaks if more sensitive files are ever added.
The fix looks for any URL that includes a /. pattern and immediately returns a 403 Forbidden response, ensuring the file cannot be accessed through the browser.

This aligns with security best practices and keeps the production environment clean and secure.

  ```
  app.js
  // Block access to hidden files or folders (e.g., /.git, /.hg, /.env)
  app.use((req, res, next) => {
    if (/\/\.[^\/]+/.test(req.url)) {
      return res.status(403).send('Access Denied');
    }
    next();
  });
  ```
Item 4: Type: X-Content-Type-Options Header Missing

   Affected Area: Static asset

   Severity: Low

   Confidence: Medium

   Recommended Fix: Add X-Content-Type-Options: nosniff header to prevent browsers from MIME-sniffing responses.

   Added a new security feature to fix the missing X-Content-Type-Options header issue, which helps prevent browsers from MIME-sniffing the content and potentially executing it incorrectly. 
  ```
  This was done by adding:
  app.use(helmet.noSniff());
  ```
This line makes sure that the server sends the header X-Content-Type-Options: nosniff with every response, which tells browsers to strictly follow the declared content types and not try to guess them. This reduces the chance of security vulnerabilities, especially related to serving files.
I also kept the existing code that blocks access to hidden files or folders (like .git or .env) to avoid exposing sensitive information.

Additionally, the helmet middleware is still configured with Content Security Policy (CSP) to restrict what resources the browser can load, and the frameguard is set to deny, which protects against clickjacking by preventing the site from being loaded in iframes.

Together, these changes improve the app’s security by fixing the missing header warning from security scans while keeping the protections against hidden file exposure and clickjacking.

Item 5: Type: Modern Web Application

   Affected Area: /sitemap.xml

   Severity: Informational

   Confidence: Medium

   Recommended Fix: No action needed.

The scanner flagged under the category Modern Web Application with a Severity of Informational. This just means that the site is structured like a modern web app, and the presence of files is typical.
It doesn't introduce any security risks on its own. Since this is just information and not a warning or error, no fix is needed.

### Reflection Checkpoint:
Fixing the vulnerabilities identified during testing was both a challenging and eye-opening experience. Initially, many of the issues like missing headers or CSP configuration seemed minor or easy to resolve. However, actually implementing the fixes correctly took some trial and error. For example, applying helmet in Express to set security headers like X-Frame-Options and X-Content-Type-Options required carefully placing middleware in the right order and making sure there weren’t conflicting settings.
Another challenge was configuring the Content Security Policy (CSP). CSP is powerful but very strict, and if not set up properly, it can break parts of the frontend—especially when using React with inline styles or scripts. I had to balance security and functionality by allowing some unsafe inline styles while still blocking risky content like external scripts or embedded objects.

OWASP ZAP also flagged a hidden file. that didn’t exist in my project. I had to learn how to block access to any potentially hidden files just in case, by writing a custom middleware. It was a good reminder that even non-existent files can be targeted by attackers.

Throughout the process, one key takeaway was that security isn't just about fixing one or two issues it’s an ongoing process. Adding headers like CSP and frameguard was a good start, but I know that vulnerabilities can still appear later, especially as dependencies change or the app grows.

Overall, this process helped me understand how small security settings can make a big difference. As a developer, it's easy to focus only on features but this reminded me why security should always be part of the development process, not just an afterthought.

## Part C: Ethical and Legal Considerations in Web Security

### Ethical Responsibilities of Security Professional
As part of this project, I conducted various security testing techniques including testing for common web vulnerabilities such as Cross-Site Scripting (XSS) and Clickjacking to identify and mitigate risks in the application.
All testing was performed in a controlled environment. At no point was testing conducted on systems, applications, or networks that I do not own or have explicit authorization to access. This aligns with ethical best practices in web security, which emphasize:

### Performing security testing only on authorized systems
- Avoiding any actions that could lead to data leakage, service disruption, or unauthorized access
- Using security tools like OWASP ZAP in a way that respects boundaries and does not affect others
- Logging and fixing vulnerabilities responsibly, without exposing them to others or exploiting them

Security professionals and students learning these skills have a responsibility to use their knowledge ethically and legally, and I have done my best to uphold those values during this phase of development.

### Legal Implications of Security Testing
While fixing and testing this app, I followed legal and ethical guidelines. All testing (e.g., XSS and OWASP ZAP scans) was done only on my own project to avoid breaking laws like the Computer Misuse Act (UK) or CFAA (US).
Even though this is a student project, I considered data privacy laws like the GDPR and Data Protection Act. 

Following privacy and legal standards, even in development, is good practice.

### Reflection Checkpoint – Ethics & Data Privacy
While testing my application, I made sure to follow ethical standards by only performing security tests like XSS and vulnerability scans on my own project in a controlled environment. I didn’t target any third-party systems to avoid legal and ethical violations.
To protect user data, I added middleware to block access to sensitive files (e.g., .env) and implemented security headers using Helmet to reduce risks like XSS and clickjacking. Even though this is a student project, I treated it seriously by considering data privacy regulations like GDPR and following the principle of least privilege.

These steps helped ensure that my testing was responsible, legal, and aligned with best practices in web security.

## Part D: Document the Security Process

### Security Testing 

To test the application’s security, I used a combination of manual and automated methods Please refer to Part A of Read Me for details.

### Vulnerability Fixes

For each vulnerability found, I applied targeted fixes. Please refer to Part B of the Read Me for details.

### Testing Tools

OWASP ZAP: Automated vulnerability scanner used to identify security issues in the web app.

Browser DevTools: To inspect HTTP headers and test client-side behaviors.

Each tool helped identify weaknesses or verify that applied fixes were effective, ensuring a thorough security review.

### Lessons Learned

Automating scans with OWASP ZAP saved time and caught issues I might have missed manually.

Configuring security headers correctly required understanding the balance between strict security and app functionality.

Blocking hidden files is a simple but often overlooked security step.

Continuous learning and testing are key, since security threats evolve and need ongoing attention.

Please refer to PART A, B and C for reflection 

---------------------------------End of Phase 4 Read ME ----------------------------------------------
# [CPRG-312] Web Security: Project Phase 4

This repository contains code for React Frontend **(UploadBox)** and Express Backend **(ExpressApp)**.  
Check the **README.md** file for each of these project to understand how to run these projects.  
To run this project you will need MongoDB, so please install if you don't have it.

**Note**

> In _Project Phase 4_, you have to identify the security issues in your project using a security testing tool.  
> But some students don't have a UI in their project and having a UI makes it easy to run **OWASP ZAP** tool.  
> So I have created these project, basically I took the code of _ABAC lab_ and add a react frontend to it.
