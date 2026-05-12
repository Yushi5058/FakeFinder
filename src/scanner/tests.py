from django.test import TestCase
from .views import _root_domain
from .utils import parse_eml_in_memory
from django.core.files.uploadedfile import SimpleUploadedFile

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
