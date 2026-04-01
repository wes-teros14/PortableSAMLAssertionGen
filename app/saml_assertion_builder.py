"""
Core SAML 2.0 Assertion builder and signer.
Replicates the behavior of SAMLAssertionGenerator.java using lxml + signxml.
"""

import base64
import uuid
from datetime import datetime, timedelta, timezone

from lxml import etree
from signxml import XMLSigner, methods
from cryptography.hazmat.primitives.serialization import load_der_private_key

# Namespaces
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
XS_NS = "http://www.w3.org/2001/XMLSchema"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

NSMAP = {
    "saml": SAML_NS,
    "xs": XS_NS,
    "xsi": XSI_NS,
}

SAML = "{%s}" % SAML_NS
XSI = "{%s}" % XSI_NS


def _fmt_dt(dt: datetime) -> str:
    """Format datetime as ISO 8601 UTC with milliseconds, matching Joda DateTime output."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _b64decode_lenient(data: str) -> bytes:
    """Base64 decode with lenient padding, matching Apache Commons Base64.decodeBase64()."""
    # Add padding if needed
    missing = len(data) % 4
    if missing:
        data += "=" * (4 - missing)
    return base64.b64decode(data)


def _parse_private_key(private_key_string: str):
    """
    Parse the private key using the same double-encoding scheme as the Java version.
    Java lines 276-286:
      1. Base64 decode the property value to a UTF-8 string
      2. Split on '###', take the first part
      3. Base64 decode again to get raw PKCS#8 DER bytes
    """
    # Step 1: Base64 decode to UTF-8 string
    decoded_str = _b64decode_lenient(private_key_string).decode("utf-8")
    # Step 2: Split on '###'
    parts = decoded_str.split("###")
    if len(parts) == 2:
        key_b64 = parts[0]
    else:
        key_b64 = decoded_str
    # Step 3: Base64 decode to get PKCS#8 DER bytes
    pkcs8_der = _b64decode_lenient(key_b64)
    # Step 4: Load as RSA private key
    return load_der_private_key(pkcs8_der, password=None)


def build_assertion(client_id: str, user_id: str, token_url: str,
                    expire_in_minutes: int, use_username_as_user_id: bool) -> etree._Element:
    """Build an unsigned SAML 2.0 Assertion XML element."""
    now = datetime.now(timezone.utc)
    assertion_id = str(uuid.uuid4())
    session_index = str(uuid.uuid4())

    not_before = now - timedelta(minutes=10)
    not_on_or_after = now + timedelta(minutes=expire_in_minutes)

    # Root Assertion element
    assertion = etree.Element(SAML + "Assertion", nsmap=NSMAP)
    assertion.set("ID", assertion_id)
    assertion.set("IssueInstant", _fmt_dt(now))
    assertion.set("Version", "2.0")

    # Issuer
    issuer = etree.SubElement(assertion, SAML + "Issuer")
    issuer.text = "www.successfactors.com"

    # Subject
    subject = etree.SubElement(assertion, SAML + "Subject")
    name_id = etree.SubElement(subject, SAML + "NameID")
    name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
    name_id.text = user_id

    subject_confirmation = etree.SubElement(subject, SAML + "SubjectConfirmation")
    subject_confirmation.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    sconf_data = etree.SubElement(subject_confirmation, SAML + "SubjectConfirmationData")
    sconf_data.set("NotOnOrAfter", _fmt_dt(not_on_or_after))
    sconf_data.set("Recipient", token_url)

    # Conditions
    conditions = etree.SubElement(assertion, SAML + "Conditions")
    conditions.set("NotBefore", _fmt_dt(not_before))
    conditions.set("NotOnOrAfter", _fmt_dt(not_on_or_after))

    audience_restriction = etree.SubElement(conditions, SAML + "AudienceRestriction")
    audience = etree.SubElement(audience_restriction, SAML + "Audience")
    audience.text = "www.successfactors.com"

    # AuthnStatement
    authn_statement = etree.SubElement(assertion, SAML + "AuthnStatement")
    authn_statement.set("AuthnInstant", _fmt_dt(now))
    authn_statement.set("SessionIndex", session_index)

    authn_context = etree.SubElement(authn_statement, SAML + "AuthnContext")
    authn_context_class_ref = etree.SubElement(authn_context, SAML + "AuthnContextClassRef")
    authn_context_class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # AttributeStatement - api_key
    attr_statement = etree.SubElement(assertion, SAML + "AttributeStatement")
    api_key_attr = etree.SubElement(attr_statement, SAML + "Attribute")
    api_key_attr.set("Name", "api_key")
    api_key_value = etree.SubElement(api_key_attr, SAML + "AttributeValue")
    api_key_value.set(XSI + "type", "xs:string")
    api_key_value.text = client_id

    # Optional: use_username attribute
    if use_username_as_user_id:
        username_stmt = etree.SubElement(assertion, SAML + "AttributeStatement")
        username_attr = etree.SubElement(username_stmt, SAML + "Attribute")
        username_attr.set("Name", "use_username")
        username_value = etree.SubElement(username_attr, SAML + "AttributeValue")
        username_value.set(XSI + "type", "xs:string")
        username_value.text = "true"

    return assertion


def sign_assertion(assertion: etree._Element, private_key) -> etree._Element:
    """Sign the SAML assertion with RSA-SHA256 using an enveloped signature."""
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    signed = signer.sign(assertion, key=private_key)
    return signed


def generate_signed_assertion(client_id: str, user_id: str, token_url: str,
                              private_key_string: str, expire_in_minutes: int = 10,
                              use_username_as_user_id: bool = False) -> str:
    """
    Generate a signed SAML 2.0 assertion and return it as a Base64-encoded string.
    This is the main entry point matching SAMLAssertionGenerator.generateSignedSAMLAssertion().
    """
    assertion = build_assertion(client_id, user_id, token_url,
                                expire_in_minutes, use_username_as_user_id)
    private_key = _parse_private_key(private_key_string)
    signed_assertion = sign_assertion(assertion, private_key)

    # Serialize to XML string, then Base64 encode
    xml_bytes = etree.tostring(signed_assertion, xml_declaration=False, encoding="unicode")
    return base64.b64encode(xml_bytes.encode("utf-8")).decode("utf-8")
