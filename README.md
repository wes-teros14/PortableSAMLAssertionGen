**The Problem**

Working with SuccessFactors APIs requires a signed SAML 2.0 bearer assertion to get an OAuth token. The standard tool for this is the SAMLAssertionGen Java project — but it requires a JDK, Maven, and command-line access. On locked-down corporate laptops, that's a dead end.


**The Solution**

I rewrote it as a portable Windows GUI. Same assertion logic, same XML structure, same RSA-SHA256 signature — just easier to run.

No installation. Unzip and double-click SAMLAssertionGen.bat. Python runtime is bundled.
GUI instead of CLI. Fill in the fields, click Generate, copy to clipboard.
Same properties file format. Drop in your existing SAMLAssertion.properties and it auto-loads.



**Setup**

Unzip the portable folder anywhere on your machine
Edit SAMLAssertion.properties:

tokenUrl = Your SuccessFactors OAuth token endpoint
clientId = Your registered client ID
userId = The user to assert (NameID)
userName = Fallback if userId is empty
privateKey = Base64-encoded PKCS#8 RSA private key
expireInMinutes = Assertion validity window (default: 10)

Run SAMLAssertionGen.bat — the GUI opens with your values pre-filled
Click Generate Assertion, then Copy to Clipboard


**Using the Assertion**

POST {tokenUrl}
Content-Type: application/x-www-form-urlencoded

company_id={companyId}
client_id={clientId}
grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer
assertion={Base64 string}
Technical Notes
The XML structure mirrors the Java original exactly: Issuer and Audience set to www.successfactors.com, NotBefore backdated 10 minutes for clock skew, enveloped XML DSIG with RSA-SHA256. Private key parsing follows the same double-Base64 + ### split scheme. Libraries: lxml, signxml, cryptography — all bundled.
Security Reminders

Never commit your properties file. It contains your private key.
Treat the generated assertion like a password, it grants API access until expiry.
Keep expiration short. 10 minutes is the right default for testing.


