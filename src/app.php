<?php
declare(strict_types=1);

define('BLINK_URL', rtrim(getenv('BLINK_URL') ?: 'http://localhost:8000', '/'));
define('BLINK_BASE', rtrim((string)parse_url(BLINK_URL, PHP_URL_PATH), '/'));
define('BLINK_DB', dirname(__DIR__).'/var/blink.sqlite');
if (!is_dir(dirname(__DIR__).'/var/sessions')) mkdir(dirname(__DIR__).'/var/sessions',0700,true);


if (session_status() !== PHP_SESSION_ACTIVE) {
    // Keep Blink sessions separate from the shared 24-minute PHP cleanup.
    ini_set('session.gc_maxlifetime', '2592000');
    ini_set('session.gc_probability', '1');
    ini_set('session.gc_divisor', '100');
    session_save_path(dirname(__DIR__).'/var/sessions');
    session_name('blink_session');
    session_set_cookie_params([
        'lifetime' => 60 * 60 * 24 * 30,
        'path' => BLINK_BASE . '/',
        'secure' => str_starts_with(BLINK_URL, 'https://'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; form-action 'self'; frame-ancestors 'self'; base-uri 'self'");

function db(): PDO {
    static $db;
    if ($db instanceof PDO) return $db;
    $db = new PDO('sqlite:' . BLINK_DB);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec('PRAGMA foreign_keys = ON');
    $db->exec('PRAGMA journal_mode = WAL');
    $db->exec('PRAGMA busy_timeout = 5000');
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        bio TEXT NOT NULL DEFAULT '',
        is_admin INTEGER NOT NULL DEFAULT 0,
        terms_accepted_at TEXT,
        terms_version TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS blinks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        body TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'Other',
        tags TEXT NOT NULL DEFAULT '',
        view_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blink_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (blink_id) REFERENCES blinks(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
        key TEXT PRIMARY KEY,
        hits INTEGER NOT NULL DEFAULT 0,
        window_start INTEGER NOT NULL
    )");
    $db->exec('CREATE INDEX IF NOT EXISTS idx_blinks_created ON blinks(created_at DESC)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_blinks_user ON blinks(user_id, created_at DESC)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_comments_blink ON comments(blink_id, created_at ASC)');
    $db->exec("CREATE TABLE IF NOT EXISTS category_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)");
    $columns = $db->query('PRAGMA table_info(blinks)')->fetchAll();
    if (!in_array('view_count', array_column($columns, 'name'), true)) {
        $db->exec('ALTER TABLE blinks ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0');
    }
    return $db;
}

function e(?string $value): string { return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function u(string $path = ''): string { return BLINK_BASE . ($path === '' ? '/' : '/' . ltrim($path, '/')); }
function redirect(string $path): never { header('Location: ' . (str_starts_with($path, '/') ? $path : u($path)), true, 303); exit; }
function current_user(): ?array {
    if (empty($_SESSION['user_id'])) return null;
    $stmt = db()->prepare('SELECT id, name, username, email, bio, created_at, is_admin FROM users WHERE id = ?');
    $stmt->execute([(int)$_SESSION['user_id']]);
    return $stmt->fetch() ?: null;
}
function is_admin(?array $user): bool { return $user && (int)($user['is_admin']??0)===1; }
function require_user(): array {
    $user = current_user();
    if (!$user) { flash('info', 'Sign in to continue.'); redirect('login?return=' . urlencode($_SERVER['REQUEST_URI'] ?? u())); }
    return $user;
}
function csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(24));
    return $_SESSION['csrf'];
}
function verify_csrf(): void {
    if (!isset($_POST['csrf']) || !hash_equals(csrf(), (string)$_POST['csrf'])) {
        // Reject the submission, then give authentication forms a fresh token.
        $authPath = path_now();
        if (in_array($authPath, ['/login', '/register'], true)) {
            flash('info', 'That form expired. Please enter your details and try again.');
            $target = $authPath;
            if ($authPath === '/login') {
                $return = valid_return((string)($_GET['return'] ?? $_POST['return'] ?? u()));
                $target .= '?return=' . urlencode($return);
            }
            redirect($target);
        }
        http_response_code(419);
        render_error('That page expired', 'Refresh the page and try again.',419);
    }
}
function flash(string $type, string $message): void { $_SESSION['flash'][] = [$type, $message]; }
function take_flashes(): array { $f = $_SESSION['flash'] ?? []; unset($_SESSION['flash']); return $f; }
function path_now(): string {
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    if (str_starts_with($path, BLINK_BASE)) $path = substr($path, strlen(BLINK_BASE));
    return '/' . trim($path, '/');
}
function slugify(string $title): string {
    $slug = strtolower(trim(preg_replace('/[^a-zA-Z0-9]+/', '-', iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $title) ?: $title), '-'));
    if ($slug === '') $slug = 'blink';
    $base = substr($slug, 0, 70);
    $slug = $base;
    $n = 2;
    $stmt = db()->prepare('SELECT 1 FROM blinks WHERE slug = ?');
    while (true) {
        $stmt->execute([$slug]);
        if (!$stmt->fetchColumn()) return $slug;
        $slug = $base . '-' . $n++;
    }
}
function excerpt(string $text, int $length = 180): string {
    $plain = trim(preg_replace('/\s+/', ' ', $text));
    return mb_strlen($plain) <= $length ? $plain : rtrim(mb_substr($plain, 0, $length - 1)) . '…';
}
function display_text(string $text): string {
    $safe = e($text);
    $safe = preg_replace_callback('~https?://[^\s<]+~iu', function ($m) {
        $url = rtrim($m[0], '.,;:!?)');
        $tail = substr($m[0], strlen($url));
        return '<a href="' . e($url) . '" target="_blank" rel="ugc nofollow noopener">' . e($url) . '</a>' . e($tail);
    }, $safe);
    return nl2br($safe);
}
function blink_inline(string $text, int $depth = 0): string {
    if ($depth > 8) return e($text);
    $pattern = '~https?://[^\s<>]+|\*\*(?=\S)(.+?)\*\*|__(?=\S)(.+?)__|(?<!\*)\*(?=\S)([^\n]+?)\*(?!\*)~u';
    $out = ''; $pos = 0;
    preg_match_all($pattern, $text, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
    foreach ($matches as $m) {
        $out .= e(substr($text, $pos, $m[0][1] - $pos));
        $token = $m[0][0];
        if (preg_match('~^https?://~i', $token)) {
            $url = rtrim($token, '.,;:!?)');
            $out .= '<a href="' . e($url) . '" target="_blank" rel="ugc nofollow noopener">' . e($url) . '</a>' . e(substr($token, strlen($url)));
        } else {
            $tag = str_starts_with($token, '**') ? 'strong' : (str_starts_with($token, '__') ? 'u' : 'em');
            $n = $tag === 'em' ? 1 : 2;
            $out .= '<' . $tag . '>' . blink_inline(substr($token, $n, -$n), $depth + 1) . '</' . $tag . '>';
        }
        $pos = $m[0][1] + strlen($token);
    }
    return $out . e(substr($text, $pos));
}
function display_blink(string $text): string { return nl2br(blink_inline($text)); }

// Approximate unique views: one read per Blink session, with no visitor log.
function record_blink_view(array &$blink): void {
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') return;
    $id = (int)$blink['id'];
    if (!empty($_SESSION['viewed_blinks'][$id])) return;
    db()->prepare('UPDATE blinks SET view_count = view_count + 1 WHERE id = ?')->execute([$id]);
    $_SESSION['viewed_blinks'][$id] = true;
    $q = db()->prepare('SELECT view_count FROM blinks WHERE id = ?');
    $q->execute([$id]);
    $blink['view_count'] = (int)$q->fetchColumn();
}

function avatar(string $name): string {
    $parts = preg_split('/\s+/', trim($name));
    $initials = '';
    foreach (array_slice($parts, 0, 2) as $part) $initials .= mb_strtoupper(mb_substr($part, 0, 1));
    return $initials ?: 'B';
}
function time_ago(string $date): string {
    $seconds = max(1, time() - strtotime($date));
    foreach ([[31536000,'year'],[2592000,'month'],[604800,'week'],[86400,'day'],[3600,'hour'],[60,'minute']] as [$unit,$label]) {
        if ($seconds >= $unit) { $n = (int)floor($seconds/$unit); return $n . ' ' . $label . ($n === 1 ? '' : 's') . ' ago'; }
    }
    return 'just now';
}
function rate_limit(string $action, int $max, int $window): bool {
    $key = hash('sha256', $action . '|' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    $now = time();
    $stmt = db()->prepare('SELECT hits, window_start FROM rate_limits WHERE key = ?');
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    if (!$row || $now - (int)$row['window_start'] > $window) {
        db()->prepare('INSERT INTO rate_limits(key,hits,window_start) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET hits=1, window_start=excluded.window_start')->execute([$key,$now]);
        return true;
    }
    if ((int)$row['hits'] >= $max) return false;
    db()->prepare('UPDATE rate_limits SET hits = hits + 1 WHERE key = ?')->execute([$key]);
    return true;
}
function valid_return(string $value): string {
    if (preg_match('/[\\\\\x00-\x20]/', $value) || str_starts_with($value, '//')) return u();
    return str_starts_with($value, BLINK_BASE . '/') ? $value : u();
}
function route_url(): string { return BLINK_URL . substr($_SERVER['REQUEST_URI'] ?? u(), strlen(BLINK_BASE)); }

function page_start(string $title, string $description, string $canonical = '', string $robots = 'index, follow', string $schema = ''): void {
    $user = current_user();
    $canonical = $canonical ?: BLINK_URL . (path_now() === '/' ? '/' : path_now());
    $fullTitle = $title === 'Blink' ? 'Blink — Share Anything' : $title . ' | Blink';
    header('Cache-Control: private, no-store');
    $flashes = take_flashes();
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . e($fullTitle) . '</title><meta name="description" content="' . e($description) . '"><meta name="robots" content="' . e($robots) . '">';
    echo '<link rel="canonical" href="' . e($canonical) . '"><meta name="theme-color" content="#7157ff">';
    echo '<meta property="og:type" content="website"><meta property="og:site_name" content="Blink"><meta property="og:title" content="' . e($fullTitle) . '"><meta property="og:description" content="' . e($description) . '"><meta property="og:url" content="' . e($canonical) . '">';
    echo '<meta name="twitter:card" content="summary"><link rel="icon" href="' . u('favicon.svg?v=2') . '" type="image/svg+xml"><link rel="sitemap" type="application/xml" href="' . u('sitemap.xml') . '">';
    echo '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">';
    echo '<meta name="google-site-verification" content="93bUZ70Agb9jYJHt5DUq4tm6UcUy08fKGW-k5rg1ORM">';
    echo '<link rel="stylesheet" href="' . u('style.css?v=1.2') . '">';
    if ($schema) echo '<script type="application/ld+json">' . $schema . '</script>';
    echo '</head><body><header class="topbar"><div class="shell nav-wrap"><a class="logo" href="' . u() . '" aria-label="Blink home"><span class="logo-mark"><svg class="blink-symbol" viewBox="0 0 48 48" fill="none" aria-hidden="true"><path d="M28 10H14a6 6 0 0 0-6 6v16a6 6 0 0 0 6 6h16a6 6 0 0 0 6-6V22" stroke="currentColor" stroke-width="3.5" stroke-linecap="round"/><path d="M18 29 39 8M28 8h11v11" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M15 19h7M15 24h3" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/></svg></span><span>blink</span></a>';
    echo '<nav class="nav-pages" aria-label="Main navigation"><a href="' . u('about') . '">About</a><a href="' . u('changelog') . '">Change Log</a></nav>';
    echo '<form class="nav-search" action="' . u() . '" method="get"><label class="sr-only" for="global-q">Search Blink</label><svg aria-hidden="true" viewBox="0 0 24 24"><path d="m21 21-4.6-4.6m2.1-5.4A7.5 7.5 0 1 1 3.5 11a7.5 7.5 0 0 1 15 0Z"/></svg><input id="global-q" name="q" value="' . e($_GET['q'] ?? '') . '" placeholder="Search blinks…"></form>';
    echo '<nav class="nav-actions" aria-label="Account">';
    if ($user) {
        echo '<a class="nav-link account-link" href="' . u('u/' . rawurlencode($user['username'])) . '" title="Your profile">@' . e($user['username']) . '</a><a class="button button-primary button-small" href="' . u('new') . '">+ New blink</a>';
        echo '<form action="' . u('logout') . '" method="post"><input type="hidden" name="csrf" value="' . csrf() . '"><button class="icon-button" title="Log out" aria-label="Log out">↗</button></form>';
    } else {
        echo '<a class="nav-link" href="' . u('login') . '">Log in</a><a class="button button-primary button-small" href="' . u('register') . '">Join Blink</a>';
    }
    echo '</nav><span class="nav-status-slot" aria-hidden="true"></span></div></header>';
    echo '<main id="main">';
    if ($flashes) { echo '<div class="shell flash-stack">'; foreach ($flashes as [$type,$message]) echo '<div class="flash flash-' . e($type) . '">' . e($message) . '</div>'; echo '</div>'; }
}
function page_end(): void {
    echo '</main><footer><div class="shell footer-inner"><a class="logo footer-logo" href="'.u().'">blink</a><div class="forge-attribution"><p>Self-hosted Blink</p></div><nav aria-label="Footer"><a href="'.u('about').'">About</a><a href="'.u('legal').'">Legal</a>';
    if(current_user())echo '<a href="'.u('account').'">Account settings</a>';
    if(is_admin(current_user()))echo '<a href="'.u('admin/requests').'">Category requests</a>';
    echo '</nav></div></footer><script src="'.u('app.js?v=1.2').'" defer></script>';
    echo '</body></html>';
}
function render_error(string $title, string $message, int $status = 400): never {
    http_response_code($status);
    page_start($title, $message, '', 'noindex, follow');
    echo '<section class="shell narrow error-page"><span class="giant-code">' . $status . '</span><h1>' . e($title) . '</h1><p>' . e($message) . '</p><a class="button button-primary" href="' . u() . '">Back to Blink</a></section>';
    page_end(); exit;
}
function blink_card(array $b): void {
    echo '<article class="blink-card"><div class="card-top"><a class="mini-avatar" href="' . u('u/' . rawurlencode($b['username'])) . '">' . e(avatar($b['name'])) . '</a><div><a class="author" href="' . u('u/' . rawurlencode($b['username'])) . '">' . e($b['name']) . '</a><span class="meta">@' . e($b['username']) . ' · ' . e(time_ago($b['created_at'])) . '</span></div><span class="category-pill">' . e($b['category']) . '</span></div>';
    echo '<a class="card-body" href="' . u('b/' . rawurlencode($b['slug'])) . '"><h2>' . e($b['title']) . '</h2><p>' . e(excerpt($b['body'], 230)) . '</p></a>';
    if ($b['tags']) { echo '<div class="tags">'; foreach (array_filter(array_map('trim', explode(',', $b['tags']))) as $tag) echo '<a href="' . u() . '?tag=' . urlencode($tag) . '">#' . e($tag) . '</a>'; echo '</div>'; }
    echo '<div class="card-foot"><span class="view-count" title="One view per browser session; counts started October 5, 2026.">' . number_format((int)$b['view_count']) . ' ' . ((int)$b['view_count'] === 1 ? 'view' : 'views') . '</span><a href="' . u('b/' . rawurlencode($b['slug'])) . '"><span>◯</span> ' . (int)$b['comment_count'] . ' ' . ((int)$b['comment_count'] === 1 ? 'comment' : 'comments') . '</a><button class="share-link" data-share="' . e(BLINK_URL . '/b/' . $b['slug']) . '">↗ Share</button><span>' . number_format(max(1, (int)$b['word_count'])) . ' words</span></div></article>';
}

$path = path_now();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($path === '/sitemap.xml') {
    header('Content-Type: application/xml; charset=UTF-8');
    $items = db()->query('SELECT slug, updated_at FROM blinks ORDER BY updated_at DESC')->fetchAll();
    echo '<?xml version="1.0" encoding="UTF-8"?>';
    echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';
    echo '<url><loc>' . BLINK_URL . '/</loc><changefreq>daily</changefreq></url>';
    foreach(['legal','terms','privacy'] as $legal)echo '<url><loc>'.BLINK_URL.'/'.$legal.'</loc><changefreq>monthly</changefreq></url>';
    echo '<url><loc>' . BLINK_URL . '/about</loc><changefreq>monthly</changefreq></url><url><loc>' . BLINK_URL . '/changelog</loc><changefreq>monthly</changefreq></url>';
    foreach ($items as $item) {
        echo '<url><loc>' . BLINK_URL . '/b/' . htmlspecialchars($item['slug'], ENT_XML1, 'UTF-8') . '</loc><lastmod>' . gmdate('Y-m-d', strtotime($item['updated_at'])) . '</lastmod></url>';
    }
    echo '</urlset>';
    exit;
}

if ($path === '/logout' && $method === 'POST') {
    verify_csrf();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) setcookie(session_name(), '', time() - 42000, BLINK_BASE . '/');
    session_destroy();
    session_start();
    flash('success', 'You are logged out.');
    redirect('');
}

if ($path === '/register') {
    if (current_user()) redirect('');
    $errors = [];
    if ($method === 'POST') {
        verify_csrf();
        if (!rate_limit('register', 8, 3600)) $errors[] = 'Too many attempts. Please wait and try again.';
        $name = trim((string)($_POST['name'] ?? ''));
        $username = strtolower(trim((string)($_POST['username'] ?? '')));
        $email = strtolower(trim((string)($_POST['email'] ?? '')));
        $password = (string)($_POST['password'] ?? '');
        if (mb_strlen($name) < 2 || mb_strlen($name) > 60) $errors[] = 'Use a name between 2 and 60 characters.';
        if (!preg_match('/^[a-z0-9_]{3,24}$/', $username)) $errors[] = 'Username must be 3–24 letters, numbers, or underscores.';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Enter a valid email address.';
        if (strlen($password) < 10) $errors[] = 'Password must be at least 10 characters.';
        if (($_POST['terms']??'')!=='yes') $errors[]='Confirm that you are 18 or older and agree to the Terms of Service.';
        if (!$errors) {
            try {
                $stmt = db()->prepare('INSERT INTO users(name,username,email,password_hash) VALUES(?,?,?,?)');
                $stmt->execute([$name,$username,$email,password_hash($password,PASSWORD_DEFAULT)]);
                $newId=(int)db()->lastInsertId();
                db()->prepare("UPDATE users SET terms_accepted_at=datetime('now'),terms_version='2026-09-21' WHERE id=?")->execute([$newId]);
                session_regenerate_id(true);
                $_SESSION['user_id'] = $newId;
                flash('success', 'Welcome to Blink. You can post your first blink now.');
                redirect('new');
            } catch (PDOException $e) {
                $errors[] = str_contains(strtolower($e->getMessage()), 'username') ? 'That username is already taken.' : 'That email or username is already registered.';
            }
        }
    }
    page_start('Create your account', 'Join Blink and share useful information in public, search-friendly posts.', '', 'noindex, follow');
    echo '<section class="auth-shell"><div class="auth-panel auth-art"><span class="eyebrow">A useful corner of the internet</span><h1>Know something?<br><em>Blink it.</em></h1><p>Publish an answer, walkthrough, lesson, or hard-won bit of knowledge without turning it into a whole blog.</p><div class="signal"><i></i><span>Public by default<br><small>Built to be found and shared</small></span></div></div><div class="auth-panel auth-form"><a class="back-link" href="' . u() . '">← Back to the feed</a><h2>Create your account</h2><p>Start sharing in about a minute.</p>';
    if ($errors) echo '<div class="form-errors">' . implode('', array_map(fn($x)=>'<p>'.e($x).'</p>', $errors)) . '</div>';
    echo '<form method="post" class="stack-form"><input type="hidden" name="csrf" value="' . csrf() . '"><label>Your name<input name="name" maxlength="60" required autocomplete="name" value="' . e($_POST['name'] ?? '') . '"></label><label>Username<div class="input-prefix"><span>@</span><input name="username" maxlength="24" required autocomplete="username" value="' . e($_POST['username'] ?? '') . '"></div></label><label>Email<input type="email" name="email" required autocomplete="email" value="' . e($_POST['email'] ?? '') . '"></label><label>Password<input type="password" name="password" minlength="10" required autocomplete="new-password"><small>At least 10 characters</small></label><label class="check terms-check"><input type="checkbox" name="terms" value="yes" required><span>I am 18 or older and agree to the <a href="'.u('terms').'" target="_blank" rel="noopener">Terms of Service</a>. I have read the <a href="'.u('privacy').'" target="_blank" rel="noopener">Privacy Policy</a>.</span></label><button class="button button-primary button-wide">Create account</button></form><p class="form-switch">Already have an account? <a href="' . u('login') . '">Log in</a></p></div></section>';
    page_end(); exit;
}

if ($path === '/login') {
    if (current_user()) redirect('');
    $error = '';
    $return = valid_return((string)($_GET['return'] ?? $_POST['return'] ?? u()));
    if ($method === 'POST') {
        verify_csrf();
        if (!rate_limit('login', 12, 900)) $error = 'Too many attempts. Wait a few minutes and try again.';
        $identity = strtolower(trim((string)($_POST['identity'] ?? '')));
        $password = (string)($_POST['password'] ?? '');
        if (!$error) {
            $stmt = db()->prepare('SELECT * FROM users WHERE email = ? OR username = ? LIMIT 1');
            $stmt->execute([$identity,$identity]);
            $found = $stmt->fetch();
            if ($found && password_verify($password,$found['password_hash'])) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int)$found['id'];
                redirect($return);
            }
            $error = 'That email/username and password do not match.';
        }
    }
    page_start('Log in', 'Log in to Blink to publish and comment.', '', 'noindex, follow');
    echo '<section class="auth-shell"><div class="auth-panel auth-art"><span class="eyebrow">Welcome back</span><h1>Pick up the thought.<br><em>Keep it moving.</em></h1><p>Your next useful answer does not need an introduction, a content calendar, or a fifteen-minute video.</p><div class="signal"><i></i><span>Short. Public. Useful.</span></div></div><div class="auth-panel auth-form"><a class="back-link" href="' . u() . '">← Back to the feed</a><h2>Log in to Blink</h2><p>Share Anything.</p>';
    if ($error) echo '<div class="form-errors"><p>' . e($error) . '</p></div>';
    echo '<form method="post" class="stack-form"><input type="hidden" name="csrf" value="' . csrf() . '"><input type="hidden" name="return" value="' . e($return) . '"><label>Email or username<input name="identity" required autocomplete="username" value="' . e($_POST['identity'] ?? '') . '"></label><label>Password<input type="password" name="password" required autocomplete="current-password"></label><div class="form-row"><label class="check"><input type="checkbox" checked disabled> Keep me logged in</label><a href="' . u('forgot') . '">Forgot password?</a></div><button class="button button-primary button-wide">Log in</button></form><p class="form-switch">New here? <a href="' . u('register') . '">Create an account</a></p></div></section>';
    page_end(); exit;
}

if ($path === '/forgot') {
    $sent = false;
    if ($method === 'POST') {
        verify_csrf();
        if (rate_limit('forgot', 5, 3600)) {
            $email = strtolower(trim((string)($_POST['email'] ?? '')));
            $stmt = db()->prepare('SELECT id,email,name FROM users WHERE email = ? LIMIT 1');
            $stmt->execute([$email]);
            if ($account = $stmt->fetch()) {
                $token = bin2hex(random_bytes(32));
                $hash = hash('sha256',$token);
                $expires = gmdate('Y-m-d H:i:s', time()+3600);
                db()->prepare('INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES(?,?,?)')->execute([$account['id'],$hash,$expires]);
                $link = BLINK_URL . '/reset?token=' . $token;
                $subject = 'Reset your Blink password';
                $message = "Hi {$account['name']},\n\nReset your Blink password using this link:\n{$link}\n\nThis link expires in one hour. If you did not request it, ignore this email.";
                @mail($account['email'],$subject,$message,"From: Blink <".(getenv('BLINK_MAIL_FROM') ?: 'noreply@example.invalid').">\r\nContent-Type: text/plain; charset=UTF-8");
            }
        }
        $sent = true;
    }
    page_start('Reset your password', 'Request a Blink password reset.', '', 'noindex, nofollow');
    echo '<section class="single-form"><a class="back-link" href="' . u('login') . '">← Back to login</a><div class="form-icon">↺</div><h1>Reset your password</h1>';
    if ($sent) echo '<p>If an account exists for that email, a reset link is on its way. Check your inbox and spam folder.</p><a class="button button-primary button-wide" href="' . u('login') . '">Return to login</a>';
    else echo '<p>Enter the email on your account. We will send a link that expires in one hour.</p><form method="post" class="stack-form"><input type="hidden" name="csrf" value="' . csrf() . '"><label>Email<input type="email" name="email" required autocomplete="email"></label><button class="button button-primary button-wide">Send reset link</button></form>';
    echo '</section>'; page_end(); exit;
}

if ($path === '/reset') {
    $token = (string)($_GET['token'] ?? $_POST['token'] ?? '');
    $hash = hash('sha256',$token);
    $stmt = db()->prepare("SELECT pr.*, u.email FROM password_resets pr JOIN users u ON u.id=pr.user_id WHERE pr.token_hash=? AND pr.used_at IS NULL AND pr.expires_at > datetime('now') LIMIT 1");
    $stmt->execute([$hash]);
    $reset = $stmt->fetch();
    if (!$reset) render_error('Reset link unavailable', 'This link is invalid or has expired. Request a new password reset.', 410);
    $error = '';
    if ($method === 'POST') {
        verify_csrf();
        $password = (string)($_POST['password'] ?? '');
        if (strlen($password) < 10) $error = 'Password must be at least 10 characters.';
        else {
            db()->beginTransaction();
            db()->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($password,PASSWORD_DEFAULT),$reset['user_id']]);
            db()->prepare("UPDATE password_resets SET used_at=datetime('now') WHERE id=?")->execute([$reset['id']]);
            db()->commit();
            flash('success','Password changed. You can log in now.');
            redirect('login');
        }
    }
    page_start('Choose a new password', 'Choose a new Blink password.', '', 'noindex, nofollow');
    echo '<section class="single-form"><div class="form-icon">✦</div><h1>Choose a new password</h1>';
    if ($error) echo '<div class="form-errors"><p>'.e($error).'</p></div>';
    echo '<form method="post" class="stack-form"><input type="hidden" name="csrf" value="' . csrf() . '"><input type="hidden" name="token" value="' . e($token) . '"><label>New password<input type="password" name="password" minlength="10" required autocomplete="new-password"><small>At least 10 characters</small></label><button class="button button-primary button-wide">Save new password</button></form></section>';
    page_end(); exit;
}

if ($path === '/new' || $path === '/edit') {
    $user = require_user();
    $editing = null;
    if ($path === '/edit') {
        $id = (int)($_GET['id'] ?? $_POST['id'] ?? 0);
        $stmt = db()->prepare('SELECT * FROM blinks WHERE id=? AND (user_id=? OR ?=1)');
        $stmt->execute([$id,$user['id'],is_admin($user)?1:0]);
        $editing = $stmt->fetch();
        if (!$editing) render_error('Blink not found', 'You cannot edit that blink.', 404);
    }
    $errors = [];
    if ($method === 'POST') {
        verify_csrf();
        $title = trim((string)($_POST['title'] ?? ''));
        $body = trim((string)($_POST['body'] ?? ''));
        $category = (string)($_POST['category'] ?? 'Other');
        $allowed = ['General','Gaming','Technology','Creative','Work','Life','Other'];
        if (!in_array($category,$allowed,true)) $category='Other';
        $tags = implode(',',array_slice(array_unique(array_filter(array_map(fn($t)=>trim(preg_replace('/[^a-zA-Z0-9_-]/','',$t)),explode(',',(string)($_POST['tags'] ?? ''))))),0,5));
        if (mb_strlen($title) < 5 || mb_strlen($title) > 120) $errors[]='Give your blink a title between 5 and 120 characters.';
        if (mb_strlen($body) < 20) $errors[]='Your blink should be at least 20 characters.';
        if (!$errors) {
            if ($editing) {
                db()->prepare("UPDATE blinks SET title=?,body=?,category=?,tags=?,updated_at=datetime('now') WHERE id=? AND (user_id=? OR ?=1)")->execute([$title,$body,$category,$tags,$editing['id'],$user['id'],is_admin($user)?1:0]);
                $slug=$editing['slug']; flash('success','Your blink was updated.');
            } else {
                $slug=slugify($title);
                db()->prepare('INSERT INTO blinks(user_id,title,slug,body,category,tags) VALUES(?,?,?,?,?,?)')->execute([$user['id'],$title,$slug,$body,$category,$tags]);
                flash('success','Blink published. It is public and ready to share.');
            }
            redirect('b/'.$slug);
        }
    }
    $values = ['title'=>$editing['title'] ?? ($_POST['title'] ?? ''),'body'=>$editing['body'] ?? ($_POST['body'] ?? ''),'category'=>$editing['category'] ?? ($_POST['category'] ?? 'General'),'tags'=>$editing['tags'] ?? ($_POST['tags'] ?? '')];
    page_start($editing?'Edit blink':'Create a blink', $editing?'Edit your public blink.':'Share something useful in a public, search-friendly blink.', '', 'noindex, follow');
    echo '<section class="composer-shell"><div class="composer-head"><div><span class="eyebrow">'.($editing?'Make it sharper':'New blink').'</span><h1>'.($editing?'Edit your blink':'What do you know?').'</h1><p>Skip the long introduction. Give people the useful part.</p></div><a href="' . ($editing?u('b/'.$editing['slug']):u()) . '" class="close-button" aria-label="Close">×</a></div>';
    if ($errors) echo '<div class="form-errors">' . implode('',array_map(fn($x)=>'<p>'.e($x).'</p>',$errors)) . '</div>';
    echo '<form method="post" class="composer-form"><input type="hidden" name="csrf" value="' . csrf() . '">';
    if($editing) echo '<input type="hidden" name="id" value="'.$editing['id'].'">';
    echo '<label class="title-field"><span>Title</span><input name="title" maxlength="120" required placeholder="How to beat the Ashen Warden without fire resistance" value="' . e($values['title']) . '"><small><b data-count-for="title">'.mb_strlen((string)$values['title']).'</b>/120</small></label><div class="body-field"><label for="blink-body">Your blink</label><div class="format-toolbar" role="toolbar" aria-label="Text formatting"><button type="button" data-format="**" aria-label="Bold" title="Bold (Ctrl+B)"><strong>B</strong></button><button type="button" data-format="*" aria-label="Italic" title="Italic (Ctrl+I)"><em>I</em></button><button type="button" data-format="__" aria-label="Underline" title="Underline (Ctrl+U)"><u>U</u></button><span>Select text to format it.</span></div><textarea id="blink-body" name="body" required rows="24" placeholder="Write the answer, steps, explanation, or walkthrough here. Paste full links anywhere you need them.">' . e($values['body']) . '</textarea><small><b data-count-for="body">'.mb_strlen((string)$values['body']).'</b> characters · No word limit</small><details class="format-preview"><summary>Preview formatting</summary><div class="detail-body" data-body-preview></div></details></div><div class="composer-grid"><label><span>Category<a class="request-category-link" target="_blank" rel="noopener" href="'.u('request-category').'">Request Category ↗</a></span><select name="category">';
    foreach(['General','Gaming','Technology','Creative','Work','Life','Other'] as $cat) echo '<option'.($values['category']===$cat?' selected':'').'>'.e($cat).'</option>';
    echo '</select></label><label><span>Tags <i>optional</i></span><input name="tags" maxlength="100" placeholder="boss-guide, walkthrough, rpg" value="' . e($values['tags']) . '"><small>Up to 5, separated by commas</small></label></div><div class="publish-bar"><div><strong>Public on publish</strong><span>Search engines and anyone with the link can read it.</span></div><button class="button button-primary">'.($editing?'Save changes':'Publish blink').' →</button></div></form></section>';
    page_end(); exit;
}

if (preg_match('~^/b/([a-z0-9-]+)$~',$path,$m)) {
    $stmt=db()->prepare("SELECT b.*,u.name,u.username,(SELECT COUNT(*) FROM comments c WHERE c.blink_id=b.id) comment_count FROM blinks b JOIN users u ON u.id=b.user_id WHERE b.slug=?");
    $stmt->execute([$m[1]]);
    $b=$stmt->fetch();
    if(!$b) render_error('Blink not found','This blink may have moved or been removed.',404);
    if($method==='POST'){
        $user=require_user(); verify_csrf();
        if(isset($_POST['delete_blink']) && ((int)$b['user_id']===(int)$user['id'] || is_admin($user))){
            db()->prepare('DELETE FROM blinks WHERE id=?')->execute([$b['id']]);
            flash('success','Your blink was deleted.'); redirect('');
        }
        if(isset($_POST['delete_comment'])){db()->prepare('DELETE FROM comments WHERE id=? AND blink_id=? AND (user_id=? OR ?=1)')->execute([(int)$_POST['delete_comment'],$b['id'],$user['id'],is_admin($user)?1:0]);flash('success','Comment deleted.');redirect('b/'.$b['slug'].'#comments');}
        $body=trim((string)($_POST['comment']??''));
        if(mb_strlen($body)<2 || mb_strlen($body)>3000) flash('error','Comments must be between 2 and 3,000 characters.');
        elseif(!rate_limit('comment-'.$user['id'],20,3600)) flash('error','You are commenting too quickly. Try again later.');
        else { db()->prepare('INSERT INTO comments(blink_id,user_id,body) VALUES(?,?,?)')->execute([$b['id'],$user['id'],$body]); flash('success','Comment posted.'); }
        redirect('b/'.$b['slug'].'#comments');
    }
    record_blink_view($b);
    $comments=db()->prepare('SELECT c.*,u.name,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.blink_id=? ORDER BY c.created_at ASC');
    $comments->execute([$b['id']]);
    $comments=$comments->fetchAll();
    $description=excerpt($b['body'],155);
    $schema=json_encode(['@context'=>'https://schema.org','@type'=>'Article','headline'=>$b['title'],'description'=>$description,'datePublished'=>date(DATE_ATOM,strtotime($b['created_at'])),'dateModified'=>date(DATE_ATOM,strtotime($b['updated_at'])),'author'=>['@type'=>'Person','name'=>$b['name'],'url'=>BLINK_URL.'/u/'.$b['username']],'mainEntityOfPage'=>BLINK_URL.'/b/'.$b['slug']],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT);
    page_start($b['title'],$description,BLINK_URL.'/b/'.$b['slug'],'index, follow, max-image-preview:large',$schema);
    $me=current_user();
    echo '<section class="reading-shell"><div class="reading-main"><article class="blink-detail"><div class="detail-kicker"><a href="' . u() . '?category='.urlencode($b['category']).'">'.e($b['category']).'</a><span>·</span><time datetime="'.e($b['created_at']).'">'.e(date('F j, Y',strtotime($b['created_at']))).'</time></div><h1>'.e($b['title']).'</h1><div class="detail-author"><a class="avatar" href="'.u('u/'.$b['username']).'">'.e(avatar($b['name'])).'</a><div><a href="'.u('u/'.$b['username']).'">'.e($b['name']).'</a><span>@'.e($b['username']).' · '.e(time_ago($b['created_at'])).'</span></div></div><div class="blink-stats"><span class="view-count" title="One view per browser session; counts started October 5, 2026.">'.number_format((int)$b['view_count']).' '.((int)$b['view_count']===1?'view':'views').'</span><a href="#comments">'.number_format((int)$b['comment_count']).' '.((int)$b['comment_count']===1?'comment':'comments').'</a></div><div class="detail-body">'.display_blink($b['body']).'</div>';
    if($b['tags']){echo '<div class="tags detail-tags">';foreach(array_filter(array_map('trim',explode(',',$b['tags']))) as $tag)echo '<a href="'.u().'?tag='.urlencode($tag).'">#'.e($tag).'</a>';echo '</div>';}
    echo '<div class="detail-actions"><button class="button button-soft share-link" data-share="'.e(BLINK_URL.'/b/'.$b['slug']).'">↗ Share this blink</button>';
    if($me && ((int)$me['id']===(int)$b['user_id'] || is_admin($me)))echo '<a class="button button-soft" href="'.u('edit?id='.$b['id']).'">Edit</a><form method="post" data-confirm="Delete this blink and all its comments?"><input type="hidden" name="csrf" value="'.csrf().'"><button class="text-danger" name="delete_blink" value="1">Delete</button></form>';
    echo '</div></article><section class="comments" id="comments"><div class="comments-title"><div><span class="eyebrow">Conversation</span><h2>'.count($comments).' '.(count($comments)===1?'comment':'comments').'</h2></div></div>';
    if($me)echo '<form method="post" class="comment-form"><a class="mini-avatar" href="'.u('u/'.$me['username']).'">'.e(avatar($me['name'])).'</a><div><textarea name="comment" maxlength="3000" required rows="3" placeholder="Add something useful…"></textarea><div><small>Keep it constructive.</small><button class="button button-primary button-small">Post comment</button></div></div><input type="hidden" name="csrf" value="'.csrf().'"></form>';
    else echo '<div class="comment-gate"><div><strong>Have something to add?</strong><p>Join the conversation with a free Blink account.</p></div><a class="button button-primary button-small" href="'.u('login?return='.urlencode(u('b/'.$b['slug']).'#comments')).'">Log in to comment</a></div>';
    if(!$comments)echo '<div class="empty-comments"><span>◌</span><p>No comments yet. Be the first to add something useful.</p></div>';
    foreach($comments as $c){echo '<article class="comment"><a class="mini-avatar" href="'.u('u/'.$c['username']).'">'.e(avatar($c['name'])).'</a><div><div class="comment-meta"><a href="'.u('u/'.$c['username']).'">'.e($c['name']).'</a><span>@'.e($c['username']).' · '.e(time_ago($c['created_at'])).'</span></div><p>'.display_text($c['body']).'</p>';if($me && ((int)$me['id']===(int)$c['user_id'] || is_admin($me)))echo '<form method="post" data-confirm="Delete this comment?"><input type="hidden" name="csrf" value="'.csrf().'"><button class="text-danger" name="delete_comment" value="'.$c['id'].'">Delete comment</button></form>';echo '</div></article>';}
    echo '</section></div><aside class="reading-aside"><div class="aside-card"><span class="spark">✦</span><h3>This is a blink.</h3><p>A focused unit of useful information—public, linkable, and built to be found.</p><a href="'.u('new').'">Blink something you know →</a></div><div class="aside-card quiet"><strong>Share without the overhead.</strong><p>No subreddit hunt. No thread maze. No full blog required.</p></div></aside></section>';
    page_end();exit;
}

if (preg_match('~^/u/([a-z0-9_]+)$~',$path,$m)) {
    $stmt=db()->prepare('SELECT id,name,username,bio,created_at FROM users WHERE username=?');$stmt->execute([$m[1]]);$profile=$stmt->fetch();
    if(!$profile)render_error('Profile not found','That Blink user does not exist.',404);
    $posts=db()->prepare("SELECT b.*,u.name,u.username,(SELECT COUNT(*) FROM comments c WHERE c.blink_id=b.id) comment_count,(LENGTH(TRIM(b.body))-LENGTH(REPLACE(TRIM(b.body),' ',''))+1) word_count FROM blinks b JOIN users u ON u.id=b.user_id WHERE b.user_id=? ORDER BY b.created_at DESC");$posts->execute([$profile['id']]);$posts=$posts->fetchAll();
    page_start($profile['name'].' (@'.$profile['username'].')',count($posts).' public blinks from '.$profile['name'].'.',BLINK_URL.'/u/'.$profile['username']);
    echo '<section class="profile-hero"><div class="shell profile-inner"><div class="profile-avatar">'.e(avatar($profile['name'])).'</div><div><span class="eyebrow">Blink contributor</span><h1>'.e($profile['name']).'</h1><p>@'.e($profile['username']).' · Joined '.e(date('F Y',strtotime($profile['created_at']))).'</p>'.($profile['bio']?'<div class="bio">'.e($profile['bio']).'</div>':'').'</div><div class="profile-stat"><strong>'.count($posts).'</strong><span>'.(count($posts)===1?'blink':'blinks').' shared</span></div></div></section><section class="shell feed-layout profile-feed"><div class="feed-main"><div class="section-title"><h2>Public blinks</h2></div>';
    if(!$posts)echo '<div class="empty-state"><span>✦</span><h3>No blinks yet</h3><p>When '.e($profile['name']).' posts, their blinks will appear here.</p></div>';
    foreach($posts as $post)blink_card($post);
    echo '</div></section>';page_end();exit;
}

require __DIR__.'/lab-routes.php';

if ($path === '/request-category') {
    $user=require_user(); $errors=[];
    if($method==='POST') {
        verify_csrf(); $name=trim((string)($_POST['name']??'')); $reason=trim((string)($_POST['reason']??''));
        if(mb_strlen($name)<2 || mb_strlen($name)>40) $errors[]='Use a category name between 2 and 40 characters.';
        if(mb_strlen($reason)<10 || mb_strlen($reason)>1000) $errors[]='Tell us why it would help in 10 to 1,000 characters.';
        if(!$errors && !rate_limit('category-request-'.$user['id'],5,86400)) $errors[]='You can submit up to five requests per day. Please try again tomorrow.';
        if(!$errors){$q=db()->prepare("SELECT id FROM category_requests WHERE user_id=? AND lower(name)=lower(?) AND status='pending'");$q->execute([$user['id'],$name]);if(!$q->fetch()){db()->prepare('INSERT INTO category_requests(user_id,name,reason) VALUES(?,?,?)')->execute([$user['id'],$name,$reason]);}flash('success','Category request received. We will review it; submitting a request does not automatically add a category.');redirect('request-category');}
    }
    page_start('Request Category','Suggest a category for Blink.','','noindex, follow');
    echo '<section class="shell narrow request-page"><span class="eyebrow">Help shape Blink</span><h1>Request Category</h1><p>Tell us what is missing and what people could share there.</p>';
    if($errors)echo '<div class="form-errors">'.implode('',array_map(fn($x)=>'<p>'.e($x).'</p>',$errors)).'</div>';
    echo '<form method="post" class="stack-form"><input type="hidden" name="csrf" value="'.csrf().'"><label>Category name<input name="name" maxlength="40" required value="'.e($_POST['name']??'').'"></label><label>Why would this category help?<textarea name="reason" minlength="10" maxlength="1000" rows="5" required>'.e($_POST['reason']??'').'</textarea></label><button class="button button-primary">Submit request</button></form><h2>Your requests</h2>';
    $q=db()->prepare('SELECT name,status,created_at FROM category_requests WHERE user_id=? ORDER BY id DESC LIMIT 25');$q->execute([$user['id']]);$requests=$q->fetchAll();
    if(!$requests)echo '<p>No requests yet.</p>';
    foreach($requests as $r)echo '<div class="request-row"><strong>'.e($r['name']).'</strong><span>'.e(ucfirst($r['status'])).'</span></div>';
    echo '<p><a class="text-link" href="'.u('new').'">Back to your blink</a></p></section>';page_end();exit;
}

if ($path === '/changelog') {
    page_start('Change Log', 'See what has changed in Blink, from the public feed and post form to accounts, category suggestions and privacy settings.');
    echo '<section class="about-hero shell changelog-heading"><span class="eyebrow">Made a little better</span><h1>Change <em>Log.</em></h1><p class="about-lede">A record of what changes as Blink grows.</p></section><section class="shell narrow changelog-list"><article class="change-entry"><time datetime="2026-10-05">October 5, 2026</time><h2>Version 1.2 — See how your blinks are doing.</h2><ul><li>Added view counts to each blink, shown in the feed, on profiles and on blink pages.</li><li>View counts are approximate: opening a blink counts once per browser session, so refreshing does not add more views. Counts start with this update.</li><li>View and comment counts now appear together on each blink page.</li></ul></article><article class="change-entry"><time datetime="2026-10-03">October 3, 2026</time><h2>Version 1.1 — A little more room.</h2><ul><li>Post titles are smaller, with cleaner spacing on desktop and mobile.</li><li>The writing box is bigger, with no word or character limit on blink content.</li><li>Select text to add bold, italic or underline, then preview your formatting before saving.</li></ul></article><article class="change-entry"><time datetime="2026-09-21">September 21, 2026</time><h2>Version 1.0 — Blink joins the Forge.</h2><ul><li>Blink has launched at blink.loganpendragonforge.com as part of Logan Pendragon Forge.</li><li>You can post under General or suggest a new category. Suggestions go privately to the site owner.</li><li>The post form is easier to use. You can delete your own posts, comments or account, and read the terms and privacy policy.</li><li>Visitor counts are collected on public information pages. The footer is simpler, and new signups appear in the owner dashboard.</li><li>The homepage now says: Share Anything. Blink it.</li><li>Blink has a new logo.</li><li>The homepage explains what a blink is.</li><li>The feed is simpler and shows how many blinks have been posted.</li><li>You can find About and Change Log at the top of every page.</li></ul></article><a class="text-link" href="'.u().'">Back to Blink →</a></section>';
    page_end();exit;
}

if ($path === '/about') {
    page_start('About', 'Blink is a simple public place for useful, focused information that deserves to be found.');
    echo '<section class="about-hero shell"><span class="eyebrow">The idea</span><h1>Not everything useful needs to become <em>a whole thing.</em></h1><p class="about-lede">A blink is a self-contained piece of information, given its own place and link so it can be shared with anyone. It can be a walkthrough, an explanation, a lesson, a fix, or the answer you wish had appeared when you searched.</p></section><section class="shell principles"><article><span>01</span><h2>Write the useful part</h2><p>Skip the publishing machinery. Start with what someone came to learn, then say as much as the answer requires.</p></article><article><span>02</span><h2>Own the page</h2><p>Your blink has a stable public address, your name, your links, and a clean discussion beneath it.</p></article><article><span>03</span><h2>Let it be found</h2><p>Every public blink gets a focused title, description, canonical link, and structured page built for search engines and people.</p></article></section><section class="shell about-cta"><div><span class="eyebrow">Keep it simple</span><h2>Know something? Blink it.</h2></div><a class="button button-primary" href="'.u('new').'">Create a blink →</a></section>';
    page_end();exit;
}

if ($path !== '/') render_error('Page not found','There is nothing at this address.',404);

$q=trim((string)($_GET['q']??''));
$category=trim((string)($_GET['category']??''));
$tag=trim((string)($_GET['tag']??''));
$where=[];$params=[];
if($q!==''){$where[]='(b.title LIKE ? OR b.body LIKE ? OR b.tags LIKE ?)';$like='%'.$q.'%';array_push($params,$like,$like,$like);}
if($category!==''){$where[]='b.category=?';$params[]=$category;}
if($tag!==''){$where[]="(',' || lower(b.tags) || ',') LIKE ?";$params[]='%,' . strtolower($tag) . ',%';}
$sql="SELECT b.*,u.name,u.username,(SELECT COUNT(*) FROM comments c WHERE c.blink_id=b.id) comment_count,(LENGTH(TRIM(b.body))-LENGTH(REPLACE(TRIM(b.body),' ',''))+1) word_count FROM blinks b JOIN users u ON u.id=b.user_id".($where?' WHERE '.implode(' AND ',$where):'').' ORDER BY b.created_at DESC LIMIT 50';
$stmt=db()->prepare($sql);$stmt->execute($params);$posts=$stmt->fetchAll();
$count=(int)db()->query('SELECT COUNT(*) FROM blinks')->fetchColumn();
page_start('Blink','Share a tutorial, walkthrough, explanation, fix, or useful thought without writing a whole blog post.');
echo '<section class="home-intro"><div class="shell intro-grid"><div><span class="eyebrow">Short enough to write. Useful enough to find.</span><h1>Share Anything.<br><em>Blink it.</em></h1><section class="blink-definition" aria-label="Definition of blink"><div class="definition-word"><strong>blink</strong><span>/blɪŋk/</span><em>noun</em></div><ol><li>A brief closing and opening of the eyes; a fleeting moment.</li><li><span class="definition-label">On Blink</span>A self-contained piece of information, given its own place and link so it can be shared with anyone.</li></ol></section><div class="hero-actions"><a class="button button-primary" href="'.u('new').'">Create a blink →</a><a class="text-link" href="'.u('about').'">What is a blink?</a></div></div><div class="motion-card"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="blink-glyph"><svg class="blink-symbol" viewBox="0 0 48 48" fill="none" aria-hidden="true"><path d="M28 10H14a6 6 0 0 0-6 6v16a6 6 0 0 0 6 6h16a6 6 0 0 0 6-6V22" stroke="currentColor" stroke-width="3.5" stroke-linecap="round"/><path d="M18 29 39 8M28 8h11v11" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M15 19h7M15 24h3" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/></svg><span></span></div><p>one thought<br><strong>out in the open</strong></p></div></div></section>';
echo '<section class="shell feed-layout home-feed"><div class="feed-main"><div class="filter-bar"><div><span class="eyebrow">'.($q?'Search results':'The public feed').'</span><h2>'.($q?'“'.e($q).'”':'Fresh blinks').'</h2></div><div class="filter-links"><a'.(!$category?' class="active"':'').' href="'.u().'">All</a>';
foreach(['General','Gaming','Technology','Creative','Work','Life'] as $cat)echo '<a'.($category===$cat?' class="active"':'').' href="'.u().'?category='.urlencode($cat).'">'.e($cat).'</a>';
echo '<a class="request-category-link" href="'.u('request-category').'">Request Category</a></div></div>';
if(!$posts)echo '<div class="empty-state"><span>✦</span><h3>'.($q?'Nothing matched that search':'The feed is ready').'</h3><p>'.($q?'Try a different phrase or browse all blinks.':'Be the first person to share something useful.').'</p><a class="button button-primary" href="'.($q?u():u('new')).'">'.($q?'Browse all':'Create the first blink').' →</a></div>';
foreach($posts as $post)blink_card($post);
echo '<div class="feed-stat"><strong>'.number_format($count).'</strong><span>public '.($count===1?'blink':'blinks').' so far</span></div></div></section>';
page_end();
