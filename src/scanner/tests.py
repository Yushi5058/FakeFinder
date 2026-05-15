import hashlib
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from .models import Signature, ScanReport, TrustedDomain
from .views import _root_domain, _predict
from .utils import parse_eml_in_memory

class ScannerLogicTests(TestCase):
    def test_root_domain_simple(self):
        self.assertEqual(_root_domain("google.com"), "google.com")
        self.assertEqual(_root_domain("sub.google.com"), "google.com")
        self.assertEqual(_root_domain("deep.sub.google.com"), "google.com")

    def test_root_domain_multi_part_tld(self):
        self.assertEqual(_root_domain("google.co.uk"), "google.co.uk")
        self.assertEqual(_root_domain("sub.google.co.uk"), "google.co.uk")
        self.assertEqual(_root_domain("amazon.com.br"), "amazon.com.br")

    def test_root_domain_invalid(self):
        self.assertEqual(_root_domain("localhost"), "localhost")
        self.assertEqual(_root_domain(""), "")

class EmlParsingTests(TestCase):
    def test_parse_simple_eml(self):
        eml_content = (
            b"From: Alice <alice@example.com>\n"
            b"Subject: Test Subject\n"
            b"MIME-Version: 1.0\n"
            b"Content-Type: text/plain\n"
            b"\n"
            b"Hello world! Check this: https://safe.com"
        )
        file = SimpleUploadedFile("test.eml", eml_content)
        parsed = parse_eml_in_memory(file)
        
        self.assertEqual(parsed["sender_email"], "alice@example.com")
        self.assertEqual(parsed["sender_domain"], "example.com")
        self.assertEqual(parsed["subject"], "Test Subject")
        self.assertEqual(parsed["body_text"], "Hello world! Check this: https://safe.com")
        self.assertIn("https://safe.com", parsed["urls"])

    def test_parse_invalid_eml(self):
        file = SimpleUploadedFile("test.txt", b"Not an email")
        with self.assertRaises(ValueError):
            parse_eml_in_memory(file)

class SignatureTests(TestCase):
    def setUp(self):
        # Create a known phishing URL signature
        self.phishing_url = "http://malicious-site.com/phish"
        self.url_hash = hashlib.sha256(self.phishing_url.encode('utf-8')).hexdigest()
        Signature.objects.create(
            indicator_hash=self.url_hash,
            indicator_type='URL',
            description="Known Phishing URL"
        )

        # Create a known phishing body hash
        self.phishing_body = "URGENT: Your account is suspended. Click here to verify."
        self.body_md5 = hashlib.md5(self.phishing_body.encode('utf-8')).hexdigest()
        Signature.objects.create(
            indicator_hash=self.body_md5,
            indicator_type='MD5',
            description="Known Phishing Email Body"
        )

    def test_signature_match_url(self):
        parsed_data = {
            "urls": [self.phishing_url, "https://safe.com"],
            "body_text": "Normal text",
            "sender_domain": "random.com"
        }
        risk, score = _predict(parsed_data)
        self.assertEqual(risk, "HIGH")
        self.assertEqual(score, 100)

    def test_signature_match_body(self):
        parsed_data = {
            "urls": ["https://safe.com"],
            "body_text": self.phishing_body,
            "sender_domain": "random.com"
        }
        risk, score = _predict(parsed_data)
        self.assertEqual(risk, "HIGH")
        self.assertEqual(score, 100)

    def test_no_signature_match(self):
        # Add google.com as trusted for this test
        TrustedDomain.objects.create(domain="google.com")
        
        # This will fall back to ML
        parsed_data = {
            "urls": ["https://safe.com"],
            "body_text": "Hello, how are you?",
            "sender_domain": "google.com" # Safe domain correction will apply
        }
        risk, score = _predict(parsed_data)
        # Should be MEDIUM (or LOW depending on model training)
        # Current model gives ~41 (MEDIUM)
        self.assertIn(risk, ["LOW", "MEDIUM"])
