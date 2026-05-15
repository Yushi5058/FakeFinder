from django.core.management.base import BaseCommand
from scanner.models import TrustedDomain, Signature

class Command(BaseCommand):
    help = 'Seeds initial trusted domains and phishing signatures'

    def handle(self, *args, **options):
        # 1. Seed Trusted Domains
        safe_domains = [
            "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "codeberg.org",
            "google.com", "gmail.com", "googlemail.com", "googlegroups.com",
            "microsoft.com", "outlook.com", "live.com", "hotmail.com", "office.com",
            "apple.com", "icloud.com",
            "amazon.com", "amazonaws.com",
            "linkedin.com", "twitter.com", "x.com",
            "slack.com", "dropbox.com", "zoom.us", "notion.so",
            "vercel.com", "netlify.com", "heroku.com", "cloudflare.com",
            "stackoverflow.com", "npmjs.com", "pypi.org",
            "atlassian.com", "jira.com", "confluence.com",
            "google.co.uk", "amazon.co.uk", "amazon.de", "google.fr",
        ]
        
        created_count = 0
        for domain in safe_domains:
            obj, created = TrustedDomain.objects.get_or_create(domain=domain)
            if created:
                created_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'Successfully seeded {created_count} new trusted domains.'))

        # 2. Seed some example phishing signatures (placeholder)
        # In a real scenario, these would be fetched from a threat intel API.
        signatures = [
            ('URL', '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069', 'Example Phishing URL Hash'),
            ('SHA256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Empty Body (example)'),
        ]

        sig_count = 0
        for stype, shash, desc in signatures:
            obj, created = Signature.objects.get_or_create(
                indicator_hash=shash,
                indicator_type=stype,
                defaults={'description': desc}
            )
            if created:
                sig_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'Successfully seeded {sig_count} phishing signatures.'))
