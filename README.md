# Blink

**Gold · v1.3.0 · released as-is.** Future features and maintenance are optional.

Blink is a small publishing app you can host yourself. It supports formatted posts, public links, comments, profiles, category requests and approximate session view counts.

I started Blink as a Forge lab and tried to market it. It wasn't gaining traction, and I didn't feel the idea justified the time it would take to keep pushing it. I decided to open-source it instead.

## Install

Requires PHP 8.3+ with PDO SQLite, mbstring and iconv. No database server or npm build is needed.

```sh
git clone https://github.com/loganpendragonmultiverse/blink.git
cd blink
php install.php
php -S localhost:8000 -t public router.php
```

Open http://localhost:8000 and register your account. Grant moderation with php tools/make-admin.php YOUR_EMAIL. No default account is shipped. Shell and PowerShell installers are included.

## Hosting

Serve public/ only; keep var/ and src/ outside the document root. Use Apache rewrite support or send all non-file requests to public/index.php. Set BLINK_URL to the installation origin (https://your-domain), and configure PHP mail plus BLINK_MAIL_FROM for password recovery. The local HTTP default is http://localhost:8000; secure cookies follow BLINK_URL. The operator must supply deployment contact details, terms and privacy notices. Keep var/ private and writable by the service user. Back up SQLite safely using its backup API.

Fresh installations have no posts or accounts. No analytics or private author service is enabled. Formatting supports bold, italic and underline while escaping HTML. Email delivery depends on your server; no hosted email service is included. Public content requires operator moderation.

## Development

Run python3 tests/smoke.py with PHP 8.3 on PATH. See TESTING.md.
MIT license. No production content is included.
