<?php
// HARNESS-VALIDATION v2.4.0 — PHP 7.4.x debug + ASAN.

declare(strict_types=1);

final class Gadget {
    public $ry;
    public function __destruct() {
        // On NE préserve PAS $this->ry. Le GC libère l'objet stdClass
        // après ce destructeur. Ce module mesure le grooming, PAS un UAF réel.
        Holder::$meta[] = ['dtor_called' => true];
    }
}

final class Holder {
    public static array $meta = [];
    public static array $dangling = [];
}

$gc_cycles = 0;
$t0 = hrtime(true);
$iterations = 50;

for ($i = 0; $i < $iterations; $i++) {
    $g = new Gadget();
    $g->ry = new stdClass();
    $g->ry->back = $g;               // crée un cycle (g ↔ ry)
    $id_before = spl_object_id($g->ry);
    unset($g);                        // libère la réf externe, le cycle reste
    $gc_cycles += gc_collect_cycles(); // force la collecte du cycle → libère ry

    // Grooming : réallouer des stdClass de même taille pour réoccuper le slot
    $reuse_found = false;
    for ($j = 0; $j < 8; $j++) {
        $reuse = new stdClass();
        if (spl_object_id($reuse) === $id_before) {
            $reuse_found = true;
        }
    }
    if ($reuse_found) {
        Holder::$dangling[] = ['reused' => true, 'id' => $id_before];
    }
}

// Limiter la taille des arrays pour éviter memory pressure à grande échelle
// v2.5 : array_slice (pas splice) pour préserver les clés associatives
if (count(Holder::$meta) > 100) {
    Holder::$meta = array_slice(Holder::$meta, -100, null, true);
}
if (count(Holder::$dangling) > 100) {
    Holder::$dangling = array_slice(Holder::$dangling, -100, null, true);
}

$reused = count(array_filter(
    Holder::$dangling,
    fn($d) => $d['reused'] ?? false
));

echo json_encode([
    'module'           => 'php_uaf',
    'php_version'      => PHP_VERSION,
    'iterations'       => $iterations,
    'gc_cycles'        => $gc_cycles,
    'slots_reused'     => $reused,
    'gc_reuse_proxy_ratio' => round($reused / max(1, $iterations), 2),
    'dtor_invocations' => count(Holder::$meta),
    'duration_ms'      => round((hrtime(true) - $t0) / 1e6, 2),
    'note'             => 'Mesure le grooming : cycles GC collectés + réutilisation '
                        . 'd ID spl_object_id (proxy de réutilisation de slot mémoire). '
                        . 'Ne déclenche PAS d UAF réel — un UAF réel nécessiterait un accès '
                        . 'après libération, non implémenté ici (voir README du module).',
], JSON_PRETTY_PRINT);
