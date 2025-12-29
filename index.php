<?php

declare(strict_types=1);

/**
 * Project Launcher para XAMPP htdocs.
 * Si dejas este dashboard en /htdocs/dashboard/, en /htdocs/index.php coloca:
 *   <?php header('Location: /dashboard/'); exit;
 *
 * Descripcion por proyecto (opciones):
 * 1) /<proyecto>/project.json   -> {"title":"...", "description":"...", "tags":["..."], "url":"/<proyecto>/", "hidden":false}
 * 2) /<proyecto>/project.md     -> primera linea = titulo (opcional), siguientes = descripcion corta
 */

$APP_DIR = realpath(__DIR__) ?: __DIR__;
$HTDOCS = realpath($APP_DIR . DIRECTORY_SEPARATOR . '..');
if ($HTDOCS === false || !is_dir($HTDOCS)) {
  $HTDOCS = $APP_DIR;
}
$APP_BASENAME = basename($APP_DIR);

// Config
$GIT_BIN_OVERRIDE = ''; // Ejemplo: 'C:\\Program Files\\Git\\cmd\\git.exe'
$GIT_AUTO_FETCH = false; // true = hace git fetch en cada carga (lento si hay muchos repos)
$ENABLE_GH_LIST = false; // true = intenta cargar lista de repos con gh o API; desactivalo si cuelga
$ALWAYS_SKIP_DIRS = ['.', '..'];
$IGNORE_DIRS = [
  $APP_BASENAME,
  'dashboard',
  'dashboardx',
  'phpmyadmin',
  'xampp',
  'security',
  'webalizer',
  'tmp',
  'img',
  'monitor_web'
];
$IGNORE_PREFIXES = ['.', '_']; // carpetas ocultas o internas
$MAX_DESC_LEN = 180;

session_start();
$LOGIN_USER = 'ftovar';
$LOGIN_PASS = 'unhdP*e2o';
$AUTH_TOKEN = hash('sha256', $LOGIN_USER . '|' . $LOGIN_PASS);
$cookieAuthOk = isset($_COOKIE['dash_auth']) && hash_equals($AUTH_TOKEN, (string)$_COOKIE['dash_auth']);
$loginError = null;
$isAuthenticated = !empty($_SESSION['auth_ok']) || $cookieAuthOk;
// Permitir autenticacion via token en formularios (para evitar perder sesion)
if (
  !$isAuthenticated
  && $_SERVER['REQUEST_METHOD'] === 'POST'
  && hash_equals($AUTH_TOKEN, (string)($_POST['auth_token'] ?? ''))
) {
  $isAuthenticated = true;
  $_SESSION['auth_ok'] = true;
  setcookie('dash_auth', $AUTH_TOKEN, time() + 60 * 60 * 24 * 30, '/');
}
if ($cookieAuthOk && empty($_SESSION['auth_ok'])) {
  // Rehidrata la sesion si el cookie es valido
  $_SESSION['auth_ok'] = true;
} elseif (!empty($_SESSION['auth_ok']) && !$cookieAuthOk) {
  // Si ya hay sesion pero no cookie, setea una para evitar pedir login tras POST
  setcookie('dash_auth', $AUTH_TOKEN, time() + 60 * 60 * 24 * 30, '/');
}

function h(string $s): string
{
  return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function safeJoin(string $base, string $rel): string
{
  $p = realpath($base . DIRECTORY_SEPARATOR . $rel);
  if ($p === false) return '';
  // evitar escaparse de htdocs
  if (strpos($p, $base) !== 0) return '';
  return $p;
}

function gitExec(string $projectPath, string $cmd, array &$out = []): int
{
  $out = [];
  $cd = (stripos(PHP_OS_FAMILY, 'Windows') === 0) ? 'cd /d ' : 'cd ';
  $binRaw = trim(gitBin(), "\"'");
  $binEsc = (stripos(PHP_OS_FAMILY, 'Windows') === 0) ? '"' . $binRaw . '"' : escapeshellarg($binRaw);

  $cmdSafe = $cmd;
  if (preg_match('/^git\\b/i', $cmd) === 1) {
    $safePath = str_replace('\\', '/', $projectPath);
    $safeDir = (stripos(PHP_OS_FAMILY, 'Windows') === 0) ? '"' . $safePath . '"' : escapeshellarg($safePath);
    static $safeAdded = [];
    $globalSafeCmd = '';
    $safeKey = strtolower($safePath);
    if (!isset($safeAdded[$safeKey])) {
      $safeAdded[$safeKey] = true;
      $checkCmd = 'git config --global --get safe.directory ' . $safeDir;
      $addCmd = 'git config --global --add safe.directory ' . $safeDir;
      $redir = (stripos(PHP_OS_FAMILY, 'Windows') === 0) ? '>NUL 2>&1' : '>/dev/null 2>&1';
      $globalSafeCmd = $checkCmd . ' ' . $redir . ' || ' . $addCmd . ' && ';
    }
    $safeFlag = '-c safe.directory=' . $safeDir;
    // Prepend one-time global safe.directory add (if needed), then the actual command with -c override
    $cmdSafe = $globalSafeCmd . preg_replace('/^git\\b/i', 'git ' . $safeFlag, $cmd, 1);
  }

  $replaced = 0;
  $patched = preg_replace('/^git\\b/i', $binEsc, $cmdSafe, 1, $replaced);
  if ($replaced === 0) {
    // Si no empieza con "git", deja el comando intacto
    $patched = $cmdSafe;
  }
  // Evitar prompts interactivos que cuelgan (ej. auth SSH/HTTPS)
  if (stripos(PHP_OS_FAMILY, 'Windows') === 0) {
    $full = $cd . escapeshellarg($projectPath) . ' && set "GIT_TERMINAL_PROMPT=0" && ' . $patched;
  } else {
    $full = 'GIT_TERMINAL_PROMPT=0 ' . $cd . escapeshellarg($projectPath) . ' && ' . $patched;
  }
  exec($full . ' 2>&1', $out, $code);
  return $code;
}

function ghBin(): string
{
  static $bin = null;
  if ($bin !== null) return $bin;

  $candidates = [
    'C:\\Program Files\\GitHub CLI\\gh.exe',
    'C:\\Program Files (x86)\\GitHub CLI\\gh.exe',
  ];

  // Intenta resolver via PATH
  $whereOut = [];
  $whereCode = 0;
  exec('where gh 2>NUL', $whereOut, $whereCode);
  if ($whereCode === 0 && !empty($whereOut[0])) {
    $candidates[] = trim($whereOut[0]);
  }

  foreach ($candidates as $c) {
    if ($c !== '' && is_file($c)) {
      $bin = $c;
      return $bin;
    }
  }
  $bin = 'gh';
  return $bin;
}

function gitBin(): string
{
  static $bin = null;
  if ($bin !== null) return $bin;

  $override = (string)($GLOBALS['GIT_BIN_OVERRIDE'] ?? '');
  if ($override !== '' && is_file($override)) {
    $bin = $override;
    return $bin;
  }

  $envBin = trim((string)getenv('GIT_BIN'), " \t\n\r\0\x0B\"'");
  if ($envBin !== '' && is_file($envBin)) {
    $bin = $envBin;
    return $bin;
  }

  $candidates = [
    'C:\\Program Files\\Git\\cmd\\git.exe',
    'C:\\Program Files\\Git\\bin\\git.exe',
    'C:\\Program Files\\Git\\mingw64\\bin\\git.exe',
    'C:\\Program Files\\Git\\usr\\bin\\git.exe',
    'C:\\Program Files (x86)\\Git\\cmd\\git.exe',
    'C:\\Program Files (x86)\\Git\\bin\\git.exe',
    'C:\\Program Files (x86)\\Git\\mingw64\\bin\\git.exe',
    'C:\\Program Files (x86)\\Git\\usr\\bin\\git.exe',
    'C:\\xampp\\git\\bin\\git.exe',
  ];

  // Intenta resolver via PATH
  $whereOut = [];
  $whereCode = 0;
  exec('where git 2>NUL', $whereOut, $whereCode);
  if ($whereCode === 0 && !empty($whereOut[0])) {
    $candidates[] = trim($whereOut[0]);
  }

  foreach ($candidates as $c) {
    if ($c !== '' && is_file($c)) {
      $bin = $c;
      return $bin;
    }
  }
  $bin = 'git';
  return $bin;
}

function getGitInfo(string $projectPath): array
{
  $gitDir = $projectPath . DIRECTORY_SEPARATOR . '.git';
  if (!is_dir($gitDir)) {
    return ['isRepo' => false];
  }

  $git = [
    'isRepo' => true,
    'branch' => '',
    'upstream' => '',
    'ahead' => 0,
    'behind' => 0,
    'lastFetch' => @filemtime($gitDir . DIRECTORY_SEPARATOR . 'FETCH_HEAD') ?: 0,
    'status' => 'clean', // clean | behind | ahead | diverged
  ];

  $cmdOut = [];
  if (gitExec($projectPath, 'git rev-parse --abbrev-ref HEAD', $cmdOut) === 0) {
    $git['branch'] = trim($cmdOut[0] ?? '');
  }

  // Actualiza referencias remotas antes de comparar (opcional)
  if (!empty($GLOBALS['GIT_AUTO_FETCH'])) {
    gitExec($projectPath, 'git fetch --prune --quiet');
    $git['lastFetch'] = @filemtime($gitDir . DIRECTORY_SEPARATOR . 'FETCH_HEAD') ?: $git['lastFetch'];
  }

  $cmdOut = [];
  if (gitExec($projectPath, 'git rev-parse --abbrev-ref --symbolic-full-name @{u}', $cmdOut) === 0) {
    $git['upstream'] = trim($cmdOut[0] ?? '');
  }

  if ($git['upstream'] === '') {
    $git['status'] = 'no_upstream';
    return $git;
  }

  if ($git['upstream'] !== '') {
    $cmdOut = [];
    if (gitExec($projectPath, 'git rev-list --left-right --count HEAD...' . escapeshellarg($git['upstream']), $cmdOut) === 0) {
      if (!empty($cmdOut[0])) {
        [$behind, $ahead] = array_map('intval', preg_split('/\\s+/', trim($cmdOut[0])));
        $git['behind'] = $behind;
        $git['ahead'] = $ahead;
        if ($behind > 0 && $ahead > 0) $git['status'] = 'diverged';
        elseif ($behind > 0) $git['status'] = 'behind';
        elseif ($ahead > 0) $git['status'] = 'ahead';
      }
    }
  }

  return $git;
}

function readProjectMeta(string $projectPath, string $folderName): array
{
  $defaultJson = [
    'title' => $folderName,
    'description' => '',
    'tags' => [],
    'url' => '/' . $folderName . '/',
    'hidden' => false,
  ];
  $meta = [
    'folder' => $folderName,
    'title' => $folderName,
    'description' => '',
    'tags' => [],
    'url' => '/' . $folderName . '/',
    'hidden' => false,
    'projectJson' => json_encode($defaultJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
  ];

  $jsonPath = $projectPath . DIRECTORY_SEPARATOR . 'project.json';
  if (is_file($jsonPath)) {
    $raw = file_get_contents($jsonPath);
    if ($raw !== false) {
      $data = json_decode($raw, true);
      if (is_array($data)) {
        // mezcla por defecto para exponer siempre las claves esperadas
        $data = array_merge($defaultJson, $data);
        if (!empty($data['title']) && is_string($data['title'])) $meta['title'] = $data['title'];
        if (!empty($data['description']) && is_string($data['description'])) $meta['description'] = $data['description'];
        if (!empty($data['tags']) && is_array($data['tags'])) $meta['tags'] = array_values(array_filter($data['tags'], 'is_string'));
        // URL base por defecto (raiz del proyecto)
        $meta['url'] = '/' . $folderName . '/';
        if (array_key_exists('hidden', $data)) {
          $meta['hidden'] = (bool)$data['hidden'];
        }
        $meta['projectJson'] = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        // Soporte legacy: "url"
        if (!empty($data['url']) && is_string($data['url'])) {
          $meta['url'] = $data['url'];
        }

        // Nuevo: entry_url (absoluto)
        if (!empty($data['entry_url']) && is_string($data['entry_url'])) {
          $meta['url'] = $data['entry_url'];
        }

        // Nuevo: entry (relativo al folder del proyecto)
        if (!empty($data['entry']) && is_string($data['entry'])) {
          $entry = trim($data['entry']);
          $entry = str_replace('\\', '/', $entry);
          $entry = ltrim($entry, '/'); // seguridad: evitar /al inicio

          // evitar rutas tipo ../
          if (strpos($entry, '..') === false && $entry !== '') {
            $meta['entry'] = $entry;
            $meta['url'] = '/' . $folderName . '/' . $entry;
          }
        }
      }
    }
  } else {
    // Crea un project.json vacio para poder controlar "hidden" aunque no exista aun
    if (is_writable($projectPath)) {
      @file_put_contents($jsonPath, json_encode($defaultJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    }
    $meta['projectJson'] = json_encode($defaultJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $mdPath = $projectPath . DIRECTORY_SEPARATOR . 'project.md';
    if (is_file($mdPath)) {
      $raw = file_get_contents($mdPath);
      if ($raw !== false) {
        $lines = preg_split("/\R/u", trim($raw)) ?: [];
        if (count($lines) > 0) {
          // Si la primera linea parece titulo (# ...), usala
          $first = trim($lines[0]);
          $first = ltrim($first, "# \t");
          if ($first !== '') $meta['title'] = $first;
        }
        // Descripcion = siguientes lineas no vacias (hasta 3)
        $descLines = [];
        for ($i = 1; $i < count($lines); $i++) {
          $ln = trim($lines[$i]);
          if ($ln === '') continue;
          $descLines[] = $ln;
          if (count($descLines) >= 3) break;
        }
        $meta['description'] = implode(' ', $descLines);
      }
    }
  }

  // Ultima modificacion (carpeta)
  $meta['mtime'] = @filemtime($projectPath) ?: 0;

  // Index autodetectable
  $meta['hasIndex'] = is_file($projectPath . DIRECTORY_SEPARATOR . 'index.php')
    || is_file($projectPath . DIRECTORY_SEPARATOR . 'index.html');

  $meta['git'] = getGitInfo($projectPath);

  // Si hay entry definido, valida que exista ese archivo
  if (!empty($meta['entry']) && is_string($meta['entry'])) {
    $entryFs = $projectPath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $meta['entry']);
    $meta['hasIndex'] = is_file($entryFs);
  }

  // Fallback: detectar index en subcarpetas tipicas (public, dist, build, admin)
  if (!$meta['hasIndex'] && (empty($meta['entry']) || !is_string($meta['entry']))) {
    $candidates = [
      'public/index.php',
      'public/index.html',
      'dist/index.html',
      'build/index.html',
      'admin/index.php',
      'admin/index.html',
    ];
    foreach ($candidates as $cand) {
      $candFs = $projectPath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $cand);
      if (is_file($candFs)) {
        $meta['entry'] = $cand;
        $meta['url'] = '/' . $folderName . '/' . $cand;
        $meta['hasIndex'] = true;
        break;
      }
    }
  }

  return $meta;
}

$loginTrying = ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'login');
if ($loginTrying) {
  $u = trim((string)($_POST['username'] ?? ''));
  $p = (string)($_POST['password'] ?? '');
  if ($u === $LOGIN_USER && $p === $LOGIN_PASS) {
    $_SESSION['auth_ok'] = true;
    setcookie('dash_auth', $AUTH_TOKEN, time() + 60 * 60 * 24 * 30, '/');
    header('Location: ' . ($_SERVER['REQUEST_URI'] ?? '/'));
    exit;
  } else {
    $loginError = 'Credenciales invalidas.';
  }
}

if (!$isAuthenticated && !$loginTrying) {
  ?>
  <!doctype html>
  <html lang="es">

  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Dashboard acceso</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>

  <body class="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100">
    <div class="w-full max-w-sm glass border border-white/10 rounded-2xl p-6">
      <h1 class="text-xl font-semibold mb-4">Acceso requerido</h1>
      <?php if ($loginError !== null): ?>
        <div class="mb-3 px-3 py-2 rounded-lg border border-rose-400/40 bg-rose-400/10 text-sm text-rose-50">
          <?= h($loginError) ?>
        </div>
      <?php endif; ?>
      <form method="post" action="" class="space-y-3">
        <input type="hidden" name="action" value="login">
        <div>
          <label class="text-xs text-slate-400 block mb-1">Usuario</label>
          <input name="username" class="w-full rounded-xl bg-slate-900/60 border border-white/10 px-3 py-2 outline-none focus:ring-2 focus:ring-indigo-400/40" required>
        </div>
        <div>
          <label class="text-xs text-slate-400 block mb-1">Contraseña</label>
          <input type="password" name="password" class="w-full rounded-xl bg-slate-900/60 border border-white/10 px-3 py-2 outline-none focus:ring-2 focus:ring-indigo-400/40" required>
        </div>
        <button class="w-full rounded-xl bg-indigo-500 hover:bg-indigo-400 text-slate-950 font-semibold px-4 py-3 transition">Ingresar</button>
      </form>
    </div>
  </body>

  </html>
  <?php
  exit;
}

$ghRepos = [];
$ghError = null;
if (!empty($ENABLE_GH_LIST)) {
  $ghLimit = 200; // se puede subir si tienes mas repos
  $ghCmd = escapeshellarg(ghBin()) . ' repo list --limit ' . (int)$ghLimit . ' --json nameWithOwner,sshUrl,cloneUrl';

  // Intento 1: gh CLI (requiere auth en la cuenta del servicio que corre PHP)
  $ghOut = [];
  $ghCode = 0;
  exec($ghCmd . ' 2>&1', $ghOut, $ghCode);
  if ($ghCode === 0) {
    $json = implode("\n", $ghOut);
    $data = json_decode($json, true);
    if (is_array($data)) {
      foreach ($data as $item) {
        if (!is_array($item)) continue;
        $name = (string)($item['nameWithOwner'] ?? '');
        $url = (string)($item['cloneUrl'] ?? ($item['sshUrl'] ?? ''));
        if ($name === '' || $url === '') continue;
        $ghRepos[] = ['name' => $name, 'url' => $url];
      }
    } else {
      $ghError = 'No se pudo parsear la respuesta de gh.';
    }
  } else {
    $ghError = 'No se pudieron listar repos con gh (quizas el servicio web no esta logueado). Comando: ' . $ghCmd;
  }

  // Intento 2: API directa si hay token en entorno (GITHUB_TOKEN o GH_TOKEN)
  if (count($ghRepos) === 0) {
    $token = getenv('GITHUB_TOKEN') ?: getenv('GH_TOKEN');
    if ($token !== false && $token !== '') {
      $apiUrl = 'https://api.github.com/user/repos?per_page=' . $ghLimit;
      $ctx = stream_context_create([
        'http' => [
          'method' => 'GET',
          'header' => "User-Agent: dashboard-gh\r\nAuthorization: Bearer " . $token . "\r\nAccept: application/vnd.github+json\r\n",
          'timeout' => 10,
        ],
      ]);
      $resp = @file_get_contents($apiUrl, false, $ctx);
      if ($resp !== false) {
        $data = json_decode($resp, true);
        if (is_array($data)) {
          foreach ($data as $item) {
            if (!is_array($item)) continue;
            $name = (string)($item['full_name'] ?? '');
            $url = (string)($item['clone_url'] ?? '');
            if ($name === '' || $url === '') continue;
            $ghRepos[] = ['name' => $name, 'url' => $url];
          }
          $ghError = null; // API funciono
        } else {
          $ghError = 'API GitHub sin parseo valido.';
        }
      } else {
        $ghError = 'No se pudo llamar a la API de GitHub. Revisa red/token.';
      }
    }
  }
} else {
  $ghError = 'Listado de repos desactivado (ENABLE_GH_LIST = false).';
}

$flash = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $action = (string)($_POST['action'] ?? '');
  if ($action === 'sync') {
    $folder = basename((string)($_POST['folder'] ?? ''));
    $target = safeJoin($HTDOCS, $folder);
    if ($target !== '' && is_dir($target) && is_dir($target . DIRECTORY_SEPARATOR . '.git')) {
      $out = [];
      $code = gitExec($target, 'git pull --ff-only', $out);
      $flash = [
        'type' => $code === 0 ? 'success' : 'error',
        'folder' => $folder,
        'message' => $code === 0 ? 'Sincronizado correctamente.' : 'No se pudo sincronizar.',
        'details' => implode("\n", $out),
      ];
    } else {
      $flash = [
        'type' => 'error',
        'folder' => $folder,
        'message' => 'Proyecto no valido o sin repo Git.',
        'details' => '',
      ];
    }
  } elseif ($action === 'safe_repo') {
    $folder = basename((string)($_POST['folder'] ?? ''));
    $target = safeJoin($HTDOCS, $folder);
    if ($target !== '' && is_dir($target) && is_dir($target . DIRECTORY_SEPARATOR . '.git')) {
      $cmd = 'git config --global --add safe.directory ' . escapeshellarg(str_replace('\\', '/', $target));
      $out = [];
      $code = gitExec($target, $cmd, $out);
      $flash = [
        'type' => $code === 0 ? 'success' : 'error',
        'folder' => $folder,
        'message' => $code === 0 ? 'Marcado como safe.directory' : 'No se pudo marcar safe.directory',
        'details' => implode("\n", $out),
      ];
    } else {
      $flash = [
        'type' => 'error',
        'folder' => $folder,
        'message' => 'Proyecto no valido o sin repo Git.',
        'details' => '',
      ];
    }
  } elseif ($action === 'check_env') {
    $reports = [];

    // Git
    $gitOut = [];
    $gitCode = gitExec($APP_DIR, 'git --version', $gitOut);
    $reports[] = 'git: ' . ($gitCode === 0 ? trim(implode(' ', $gitOut)) : 'ERROR -> ' . trim(implode("\n", $gitOut)));

    // GitHub CLI
    $ghBinPath = ghBin();
    $ghCmd = escapeshellarg($ghBinPath) . ' --version';
    $ghOut = [];
    $ghCode = 0;
    exec($ghCmd . ' 2>&1', $ghOut, $ghCode);
    $reports[] = 'gh: ' . ($ghCode === 0 ? trim(implode(' ', $ghOut)) : 'ERROR -> ' . trim(implode("\n", $ghOut)));

    // Token
    $token = getenv('GITHUB_TOKEN') ?: getenv('GH_TOKEN');
    if ($token !== false && $token !== '') {
      $tail = strlen($token) > 4 ? substr($token, -4) : '****';
      $reports[] = 'GITHUB_TOKEN: presente (****' . $tail . ')';
    } else {
      $reports[] = 'GITHUB_TOKEN: no definido';
    }

    $ok = ($gitCode === 0);
    $flash = [
      'type' => $ok ? 'success' : 'error',
      'folder' => '',
      'message' => $ok ? 'Check de entorno OK' : 'Check de entorno con errores',
      'details' => implode("\n", $reports),
    ];
  } elseif ($action === 'clone') {
    $repo = trim((string)($_POST['gh_repo'] ?? ''));
    $folderInput = trim((string)($_POST['folder'] ?? ''));
    if ($repo === '' || strpos($repo, ' ') !== false) {
      $flash = [
        'type' => 'error',
        'folder' => '',
        'message' => 'Selecciona un repo valido.',
        'details' => '',
      ];
    } else {
      $repoBase = basename(str_replace('\\', '/', $repo));
      $safeFolder = preg_replace('/[^A-Za-z0-9._-]/', '', $folderInput !== '' ? $folderInput : $repoBase);
      if ($safeFolder === '') $safeFolder = $repoBase;
      // Para nuevas carpetas usamos join directo (realpath falla si no existe)
      $target = rtrim($HTDOCS, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $safeFolder;
      if (str_contains($safeFolder, '..')) {
        $flash = [
          'type' => 'error',
          'folder' => $safeFolder,
          'message' => 'Nombre de carpeta invalido.',
          'details' => '',
        ];
      } elseif (file_exists($target)) {
        $flash = [
          'type' => 'error',
          'folder' => $safeFolder,
          'message' => 'Ya existe una carpeta/archivo con ese nombre.',
          'details' => '',
        ];
      } else {
        $out = [];
        $code = gitExec($HTDOCS, 'git clone --depth 1 ' . escapeshellarg($repo) . ' ' . escapeshellarg($safeFolder), $out);
      $flash = [
        'type' => $code === 0 ? 'success' : 'error',
        'folder' => $safeFolder,
        'message' => $code === 0 ? 'Repo clonado correctamente.' : 'No se pudo clonar el repo.',
        'details' => implode("\n", $out),
      ];
      }
    }
  } elseif ($action === 'update_project') {
    $folder = basename((string)($_POST['folder'] ?? ''));
    $target = safeJoin($HTDOCS, $folder);
    $jsonPath = $target !== '' ? $target . DIRECTORY_SEPARATOR . 'project.json' : '';
    if ($target === '' || !is_dir($target) || $jsonPath === '') {
      $flash = [
        'type' => 'error',
        'folder' => $folder,
        'message' => 'Proyecto no valido.',
        'details' => '',
      ];
    } else {
      $rawJson = (string)($_POST['project_json'] ?? '');
      try {
        $decoded = json_decode($rawJson, true, 512, JSON_THROW_ON_ERROR);
      } catch (Throwable $e) {
        $decoded = null;
        $flash = [
          'type' => 'error',
          'folder' => $folder,
          'message' => 'JSON invalido.',
          'details' => $e->getMessage(),
        ];
      }
      if (is_array($decoded)) {
        // mezcla con claves esperadas para no perder informacion existente
        $current = [];
        if (is_file($jsonPath)) {
          $existing = json_decode((string)@file_get_contents($jsonPath), true);
          if (is_array($existing)) $current = $existing;
        }
        $merged = array_merge($current, $decoded);
        // Normaliza tipos
        if (isset($merged['tags']) && is_array($merged['tags'])) {
          $merged['tags'] = array_values(array_filter($merged['tags'], 'is_string'));
        }
        if (isset($merged['hidden'])) {
          $merged['hidden'] = (bool)$merged['hidden'];
        }
        if (!isset($merged['title'])) $merged['title'] = $folder;
        if (!isset($merged['description'])) $merged['description'] = '';
        if (!isset($merged['url'])) $merged['url'] = '/' . $folder . '/';
        $payload = json_encode($merged, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $ok = @file_put_contents($jsonPath, $payload . "\n", LOCK_EX);
        if ($ok === false) {
          $err = error_get_last();
          $flash = [
            'type' => 'error',
            'folder' => $folder,
            'message' => 'No se pudo guardar project.json',
            'details' => isset($err['message']) ? $err['message'] : 'Error de escritura en ' . $jsonPath,
          ];
        } else {
          $flash = [
            'type' => 'success',
            'folder' => $folder,
            'message' => 'Guardado project.json',
            'details' => '',
          ];
        }
      }
    }
  }
}
$q = trim((string)($_GET['q'] ?? ''));

// Scan projects
$projects = [];
$hiddenProjects = [];
$hiddenTotal = 0;
$items = @scandir($HTDOCS);
if (is_array($items)) {
  foreach ($items as $item) {
    if (in_array($item, $ALWAYS_SKIP_DIRS, true)) continue;
    foreach ($IGNORE_PREFIXES as $pref) {
      if ($pref !== '' && str_starts_with($item, $pref)) continue 2;
    }

    $p = safeJoin($HTDOCS, $item);
    if ($p === '' || !is_dir($p)) continue;

    $isInIgnoreList = in_array($item, $IGNORE_DIRS, true);

    $meta = readProjectMeta($p, $item);

    // Filtro busqueda
    if ($q !== '') {
      $hay = mb_strtolower($meta['folder'] . ' ' . $meta['title'] . ' ' . $meta['description'] . ' ' . implode(' ', $meta['tags']));
      if (mb_strpos($hay, mb_strtolower($q)) === false) continue;
    }

    // recorta desc
    if ($meta['description'] !== '' && mb_strlen($meta['description']) > $MAX_DESC_LEN) {
      $meta['description'] = rtrim(mb_substr($meta['description'], 0, $MAX_DESC_LEN)) . '...';
    }

    $isHidden = $isInIgnoreList || !empty($meta['hidden']);
    $meta['isHidden'] = $isHidden;

    if ($isHidden) {
      $hiddenTotal++;
      $hiddenProjects[] = $meta;
      continue;
    }

    $projects[] = $meta;
  }
}

// Sort: repos mas recientes primero; proyectos sin repo al final
$sorter = function ($a, $b) {
  $aRepo = !empty($a['git']['isRepo']);
  $bRepo = !empty($b['git']['isRepo']);
  if ($aRepo && !$bRepo) return -1;
  if (!$aRepo && $bRepo) return 1;

  $aTs = max((int)($a['git']['lastFetch'] ?? 0), (int)($a['mtime'] ?? 0));
  $bTs = max((int)($b['git']['lastFetch'] ?? 0), (int)($b['mtime'] ?? 0));

  if ($aTs === $bTs) {
    return strcasecmp((string)($a['title'] ?? ''), (string)($b['title'] ?? ''));
  }
  return $bTs <=> $aTs; // Descendente
};
usort($projects, $sorter);
if (count($hiddenProjects) > 0) {
  usort($hiddenProjects, $sorter);
}

$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
$baseUrl .= ($_SERVER['HTTP_HOST'] ?? 'localhost');

function fmtDate(int $ts): string
{
  if ($ts <= 0) return '';
  return date('Y-m-d H:i', $ts);
}
?>
<!doctype html>
<html lang="es">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Local Projects</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='12' fill='%23182a4a'/><path d='M22 16h12c10 0 16 6 16 16s-6 16-16 16H22V16z' fill='%236c8cff'/><path d='M26 24h7c5 0 8 3 8 8s-3 8-8 8h-7V24z' fill='%23182a4a'/></svg>">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .glass {
      backdrop-filter: blur(10px);
      background: rgba(255, 255, 255, .06);
    }
    :root {
      color-scheme: dark;
    }
    [data-theme="light"] {
      color-scheme: light;
    }
    [data-theme="light"] body {
      background: #f5f7fb;
      color: #0f172a;
    }
    [data-theme="light"] .glass {
      background: rgba(255, 255, 255, .9);
      border-color: rgba(0, 0, 0, .05);
    }
    [data-theme="light"] .text-slate-100,
    [data-theme="light"] .text-slate-200,
    [data-theme="light"] .text-slate-300,
    [data-theme="light"] .text-slate-400 {
      color: #1f2937 !important;
    }
    [data-theme="light"] .text-slate-500 {
      color: #374151 !important;
    }
    [data-theme="light"] input,
    [data-theme="light"] select,
    [data-theme="light"] textarea {
      background: #fff !important;
      color: #0f172a !important;
      border-color: #d1d5db !important;
    }
    [data-theme="light"] .bg-slate-900\/60 {
      background-color: rgba(255, 255, 255, 0.9) !important;
    }
    [data-theme="light"] .bg-slate-950 {
      background-color: #f5f7fb !important;
    }
    [data-theme="light"] .bg-slate-800 {
      background-color: #e5e7eb !important;
      color: #0f172a;
    }
    [data-theme="light"] .border-white\/10 {
      border-color: rgba(0, 0, 0, 0.06) !important;
    }
    [data-theme="light"] .bg-slate-900\/80 {
      background-color: rgba(255, 255, 255, 0.9) !important;
      color: #0f172a;
    }
    /* Masonry responsive: 1 col mobile, 2 cols sm, 3 cols lg */
    .masonry {
      column-gap: 1rem;
      column-count: 1;
    }
    @media (min-width: 640px) {
      .masonry {
        column-count: 2;
      }
    }
    @media (min-width: 1024px) {
      .masonry {
        column-count: 3;
      }
    }
    .masonry > article {
      break-inside: avoid;
      margin-bottom: 1rem;
      display: block;
    }
    .tag-chip {
      background-color: rgba(15, 23, 42, 0.7);
      border-color: rgba(255, 255, 255, 0.16);
      color: #e2e8f0 !important;
      font-weight: 600;
    }
    [data-theme="light"] .tag-chip {
      background-color: #e0e7ff;
      border-color: #cbd5e1;
      color: #0f172a !important;
    }
    /* Badges de estado */
    .status-pill {
      font-weight: 600;
    }
    [data-theme="light"] .status-clean {
      background-color: #d1fae5;
      color: #065f46 !important;
      border-color: #6ee7b7 !important;
    }
    [data-theme="light"] .status-behind {
      background-color: #fef3c7;
      color: #92400e !important;
      border-color: #fcd34d !important;
    }
    [data-theme="light"] .status-ahead {
      background-color: #cffafe;
      color: #0e7490 !important;
      border-color: #67e8f9 !important;
    }
    [data-theme="light"] .status-diverged {
      background-color: #ffe4e6;
      color: #9f1239 !important;
      border-color: #fda4af !important;
    }
    .hidden-pill {
      font-weight: 600;
    }
    [data-theme="light"] .hidden-pill {
      background-color: #fef3c7 !important;
      color: #92400e !important;
      border-color: #fcd34d !important;
    }
    [data-theme="light"] .desc-text {
      color: #111827 !important;
    }
    /* Alertas en modo claro */
    [data-theme="light"] .flash-box {
      color: #0f172a !important;
    }
    [data-theme="light"] .flash-success {
      background: #ecfdf3 !important;
      border-color: #6ee7b7 !important;
      color: #166534 !important;
    }
    [data-theme="light"] .flash-error {
      background: #fef2f2 !important;
      border-color: #fecaca !important;
      color: #991b1b !important;
    }
    [data-theme="light"] .flash-box pre,
    [data-theme="light"] .flash-box button {
      color: #0f172a !important;
      border-color: rgba(0, 0, 0, 0.12) !important;
    }
    /* Controles del editor project.json en modo claro */
    [data-theme="light"] details {
      color: #0f172a;
    }
    [data-theme="light"] .project-editor {
      background-color: #f8fafc;
      border-color: #e2e8f0;
    }
    [data-theme="light"] .project-editor summary {
      color: #0f172a;
    }
    [data-theme="light"] .project-editor .desc-text {
      color: #0f172a !important;
    }
    [data-theme="light"] .project-editor textarea {
      background: #fff !important;
      color: #0f172a !important;
      border-color: #cbd5e1 !important;
    }
    [data-theme="light"] .project-editor .hint {
      color: #475569 !important;
    }
  </style>
</head>

<body class="min-h-screen bg-slate-950 text-slate-100">
  <div class="absolute inset-0 overflow-hidden pointer-events-none">
    <div class="absolute -top-48 -left-48 w-96 h-96 rounded-full bg-indigo-500/20 blur-3xl"></div>
    <div class="absolute top-32 -right-48 w-96 h-96 rounded-full bg-fuchsia-500/20 blur-3xl"></div>
    <div class="absolute bottom-0 left-1/3 w-[520px] h-[520px] rounded-full bg-cyan-400/10 blur-3xl"></div>
  </div>

  <header class="relative">
    <div class="max-w-6xl mx-auto px-4 pt-10 pb-6">
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 class="text-3xl md:text-4xl font-semibold tracking-tight">Proyectos locales</h1>
          <p class="text-slate-300 mt-2">
          </p>
        </div>
        <div class="text-sm text-slate-300 flex flex-wrap items-center gap-3">
          <span class="px-3 py-1 rounded-full glass border border-white/10 inline-flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
            <?= count($projects) ?> visibles
          </span>
          <button id="toggle-hidden-btn" type="button" class="px-3 py-2 rounded-xl bg-slate-900/80 border border-white/10 hover:border-white/20 transition inline-flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-amber-300"></span>
            <span id="toggle-hidden-label">Mostrar ocultos: <?= (int)$hiddenTotal ?></span>
          </button>
          <button id="theme-toggle-btn" type="button" class="px-3 py-2 rounded-xl bg-slate-900/80 border border-white/10 hover:border-white/20 transition">
            Modo claro
          </button>
          <form method="post" action="">
            <input type="hidden" name="action" value="check_env">
            <input type="hidden" name="auth_token" value="<?= h($AUTH_TOKEN) ?>">
            <button class="px-3 py-2 rounded-xl bg-slate-800 border border-white/10 hover:border-white/20 transition inline-flex items-center gap-2 text-sm text-slate-100">
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 7h-9"></path>
                <path d="M14 17H5"></path>
                <circle cx="17" cy="17" r="3"></circle>
                <circle cx="7" cy="7" r="3"></circle>
              </svg>
              Check entorno
            </button>
          </form>
        </div>
      </div>

      <form class="mt-6 glass border border-white/10 rounded-2xl p-3 md:p-4"
        method="get" action="">
        <div class="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div class="md:col-span-11">
            <input name="q" value="<?= h($q) ?>" placeholder="Buscar por nombre, titulo, tags o descripcion"
              class="w-full rounded-xl bg-slate-900/60 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-indigo-400/40">
          </div>
          <div class="md:col-span-1">
            <button class="w-full rounded-xl bg-indigo-500 hover:bg-indigo-400 text-slate-950 font-semibold px-4 py-3 transition">
              Ir
            </button>
          </div>
        </div>
      </form>
      <div class="mt-4 flex flex-wrap items-center gap-3">
        <span class="text-sm text-slate-300">Accesos rapidos:</span>
        <a class="inline-flex items-center gap-2 px-4 py-2 rounded-xl glass border border-white/10 text-slate-100 hover:border-white/20 transition"
          href="/phpmyadmin/" target="_blank" rel="noopener">
          <svg class="w-4 h-4 text-emerald-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <ellipse cx="12" cy="5" rx="7" ry="3"></ellipse>
            <path d="M5 5v7c0 1.7 3.1 3 7 3s7-1.3 7-3V5"></path>
            <path d="M5 12v7c0 1.7 3.1 3 7 3s7-1.3 7-3v-7"></path>
          </svg>
          phpMyAdmin
        </a>
        <a class="inline-flex items-center gap-2 px-4 py-2 rounded-xl glass border border-white/10 text-slate-100 hover:border-white/20 transition"
          href="/monitor_web/" target="_blank" rel="noopener">
          <svg class="w-4 h-4 text-cyan-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <rect x="3" y="4" width="18" height="13" rx="2"></rect>
            <path d="M8 21h8"></path>
            <path d="M12 17v4"></path>
            <path d="M7 9h5l2 3 2-6 1 3h3"></path>
          </svg>
          Monitor web
        </a>
      </div>
    </div>
  </header>

  <main class="relative max-w-6xl mx-auto px-4 pb-14">
    <?php if ($flash !== null): ?>
      <div class="mb-4 p-4 rounded-2xl border text-sm flash-box <?= $flash['type'] === 'success' ? 'flash-success border-emerald-400/40 bg-emerald-400/10 text-emerald-50' : 'flash-error border-rose-400/40 bg-rose-400/10 text-rose-50' ?>">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="font-semibold mb-1"><?= h($flash['message']) ?> (<?= h($flash['folder']) ?>)</div>
            <?php if (!empty($flash['details'])): ?>
              <pre class="whitespace-pre-wrap text-xs opacity-80"><?= h($flash['details']) ?></pre>
            <?php endif; ?>
          </div>
          <button onclick="this.parentElement.parentElement.remove()" class="text-xs uppercase tracking-wide px-2 py-1 rounded-lg border border-white/20">
            Cerrar
          </button>
        </div>
      </div>
    <?php endif; ?>

    <div id="sync-modal" class="hidden fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center">
      <div class="glass border border-white/10 rounded-2xl p-6 max-w-sm w-full text-center space-y-3">
        <div class="flex items-center justify-center gap-3 text-slate-100">
          <svg class="w-5 h-5 animate-spin text-indigo-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10" stroke-opacity="0.2"></circle>
            <path d="M22 12a10 10 0 0 1-10 10" stroke-linecap="round"></path>
          </svg>
          <span class="font-semibold">Sincronizando…</span>
        </div>
        <p class="text-sm text-slate-300" id="sync-modal-text">Ejecutando git pull --ff-only en el proyecto. Por favor espera.</p>
        <button id="sync-modal-close" class="hidden px-4 py-2 rounded-lg bg-slate-800 border border-white/10 text-slate-200 hover:border-white/20 transition w-full text-sm">
          Cerrar
        </button>
      </div>
    </div>

    <details class="glass border border-white/10 rounded-2xl p-5 mb-6">
      <summary class="flex items-center justify-between gap-3 cursor-pointer select-none">
        <h2 class="text-lg font-semibold inline-flex items-center gap-2">
          <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.09 3.29 9.4 7.86 10.92.58.11.79-.25.79-.56v-2c-3.2.7-3.87-1.37-3.87-1.37-.53-1.33-1.3-1.69-1.3-1.69-1.06-.72.08-.7.08-.7 1.18.08 1.8 1.21 1.8 1.21 1.04 1.78 2.73 1.26 3.4.96.1-.76.41-1.26.74-1.55-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.3 1.2-3.11-.12-.29-.52-1.46.11-3.05 0 0 .98-.31 3.2 1.19a11.2 11.2 0 0 1 2.92-.39c.99 0 1.99.13 2.92.39 2.22-1.5 3.2-1.19 3.2-1.19.64 1.59.24 2.76.12 3.05.75.81 1.2 1.85 1.2 3.11 0 4.41-2.69 5.39-5.25 5.67.42.36.8 1.07.8 2.16v3.2c0 .31.21.68.8.56A10.53 10.53 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z"/>
          </svg>
          Clonar desde GitHub
        </h2>
        <span class="text-xs text-slate-400">Abrir</span>
      </summary>
      <div class="mt-3 pt-3 border-t border-white/5 space-y-3">
        <?php if ($ghError !== null): ?>
          <div class="text-sm text-amber-300">Aviso: <?= h($ghError) ?></div>
        <?php endif; ?>
        <?php if (count($ghRepos) === 0): ?>
          <div class="text-sm text-slate-400">No se pudieron cargar repos. Asegura que <code class="font-mono">gh</code> este instalado y logueado.</div>
        <?php else: ?>
          <form class="grid grid-cols-1 md:grid-cols-12 gap-3 items-end" method="post" action="">
            <input type="hidden" name="action" value="clone">
            <input type="hidden" name="auth_token" value="<?= h($AUTH_TOKEN) ?>">
            <div class="md:col-span-7">
              <label class="text-xs text-slate-400 block mb-1">Selecciona repo</label>
              <select name="gh_repo" class="w-full rounded-xl bg-slate-900/60 border border-white/10 px-3 py-2 outline-none focus:ring-2 focus:ring-indigo-400/40">
                <?php foreach ($ghRepos as $r): ?>
                  <option value="<?= h($r['url']) ?>"><?= h($r['name']) ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="md:col-span-4">
              <label class="text-xs text-slate-400 block mb-1">Nombre de carpeta (opcional)</label>
              <input name="folder" placeholder="mi-proyecto" class="w-full rounded-xl bg-slate-900/60 border border-white/10 px-3 py-2 outline-none focus:ring-2 focus:ring-indigo-400/40">
            </div>
            <div class="md:col-span-1">
              <button class="w-full rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold px-4 py-3 transition">
                Clonar
              </button>
            </div>
          </form>
        <?php endif; ?>
      </div>
    </details>

    <?php
    $hasVisible = count($projects) > 0;
    $hasHidden = count($hiddenProjects) > 0;
    $sections = [
      ['title' => 'Proyectos', 'items' => $projects, 'isHidden' => false],
      ['title' => 'Proyectos ocultos', 'items' => $hiddenProjects, 'isHidden' => true, 'total' => $hiddenTotal],
    ];
    ?>

    <?php if (!$hasVisible && !$hasHidden): ?>
      <div class="glass border border-white/10 rounded-2xl p-8 text-slate-300">
        No encontre proyectos con esos filtros.
      </div>
    <?php endif; ?>

    <?php foreach ($sections as $section): ?>
      <?php $wrapperId = $section['isHidden'] ? 'hidden-section' : null; ?>
      <div<?= $wrapperId ? ' id="' . $wrapperId . '"' : '' ?><?= $section['isHidden'] ? ' class="hidden"' : '' ?>>
        <?php if ($section['isHidden']): ?>
          <div class="mt-8 flex items-center justify-between gap-3">
            <h3 class="text-sm uppercase tracking-wide text-slate-400"><?= h($section['title']) ?> (<?= count($section['items']) ?><?= isset($section['total']) ? ' de ' . (int)$section['total'] : '' ?>)</h3>
            <span class="text-xs text-slate-500">Incluye carpetas listadas en $IGNORE_DIRS.</span>
          </div>
        <?php endif; ?>

        <?php if (count($section['items']) > 0): ?>
          <div class="mt-4 masonry">
            <?php foreach ($section['items'] as $p): ?>
              <?php
              $git = $p['git'] ?? ['isRepo' => false];
              $activityTs = $git['isRepo']
                ? ((int)($git['lastFetch'] ?? 0) ?: (int)($p['mtime'] ?? 0))
                : (int)($p['mtime'] ?? 0);
              ?>
              <article class="glass border border-white/10 rounded-2xl p-5 hover:border-white/20 transition">
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <h2 class="text-lg font-semibold leading-snug"><?= h($p['title']) ?></h2>
                    <p class="text-xs text-slate-300 mt-1 font-mono">/<?= h($p['folder']) ?>/</p>
                  </div>
                  <div class="flex flex-col items-end gap-2">
                    <span class="text-xs px-2 py-1 rounded-full border border-white/10 text-slate-300">
                      <?= $p['hasIndex'] ? 'Listo' : 'Sin index' ?>
                    </span>
                    <?php if (!empty($section['isHidden'])): ?>
                      <span class="text-[10px] px-2 py-1 rounded-full border border-amber-400/40 bg-amber-500/10 text-amber-100 hidden-pill">Oculto</span>
                    <?php endif; ?>
                  </div>
                </div>

                <?php if (!empty($p['description'])): ?>
                  <p class="text-slate-200/90 mt-4 text-sm leading-relaxed desc-text"><?= h($p['description']) ?></p>
                <?php else: ?>
                  <p class="text-slate-400 mt-4 text-sm desc-text">Sin descripcion.</p>
                <?php endif; ?>

                <?php if (!empty($p['tags'])): ?>
                  <div class="mt-4 flex flex-wrap gap-2">
                    <?php foreach (array_slice($p['tags'], 0, 6) as $t): ?>
                      <span class="text-xs px-2 py-1 rounded-full bg-slate-900/60 border border-white/10 tag-chip">
                        <?= h($t) ?>
                      </span>
                    <?php endforeach; ?>
                  </div>
                <?php endif; ?>

                <?php if ($git['isRepo']): ?>
                  <?php
                  $status = (string)($git['status'] ?? '');
                  $statusLabel = 'Al dia';
                  $statusColor = 'bg-emerald-500/20 text-emerald-100 border-emerald-400/30';
                  $statusClass = 'status-clean';
                  $statusDot = 'bg-emerald-400';

                  if ($status === 'no_upstream') {
                    $statusLabel = 'Sin upstream';
                    $statusColor = 'bg-amber-500/20 text-amber-100 border-amber-400/40';
                    $statusClass = 'status-behind';
                    $statusDot = 'bg-amber-300';
                  } elseif ($status === 'behind') {
                    $statusLabel = 'Desactualizado';
                    $statusColor = 'bg-amber-500/20 text-amber-100 border-amber-400/40';
                    $statusClass = 'status-behind';
                    $statusDot = 'bg-rose-400';
                  } elseif ($status === 'ahead') {
                    $statusLabel = 'Adelantado';
                    $statusColor = 'bg-cyan-500/20 text-cyan-100 border-cyan-400/40';
                    $statusClass = 'status-ahead';
                    $statusDot = 'bg-rose-400';
                  } elseif ($status === 'diverged') {
                    $statusLabel = 'Desincronizado';
                    $statusColor = 'bg-rose-500/20 text-rose-100 border-rose-400/40';
                    $statusClass = 'status-diverged';
                    $statusDot = 'bg-rose-400';
                  }

                  if (empty($git['branch'])) {
                    $git['branch'] = '--';
                  }
                  ?>
                  <details class="mt-4 rounded-xl bg-slate-900/60 border border-white/10 p-3 text-xs text-slate-200">
                    <summary class="flex items-center justify-between gap-3 cursor-pointer select-none">
                      <div class="flex items-center gap-2">
                        <span class="w-2.5 h-2.5 rounded-full <?= $statusDot ?>"></span>
                        <span class="px-2 py-1 rounded-lg border <?= $statusColor ?> status-pill <?= $statusClass ?>"><?= h($statusLabel) ?></span>
                        <span class="px-2 py-1 rounded-lg bg-slate-800 border border-white/10 font-mono"><?= h($git['branch']) ?></span>
                      </div>
                      <span class="text-[11px] text-slate-400">Estado Git</span>
                    </summary>
                    <div class="mt-3 pt-3 border-t border-white/5">
                      <div class="flex items-start justify-between gap-3">
                        <div class="space-y-1">
                          <div class="text-slate-400">
                            <?= !empty($git['upstream']) ? 'Upstream: ' . h($git['upstream']) : 'Sin upstream configurado.' ?>
                          </div>
                          <div class="text-slate-400">
                            Fetch: <?= h(fmtDate((int)($git['lastFetch'] ?? 0))) ?>
                          </div>
                          <div class="text-slate-400">
                            Adelante: <?= (int)($git['ahead'] ?? 0) ?> | Atras: <?= (int)($git['behind'] ?? 0) ?>
                          </div>
                        </div>
                        <div class="flex flex-col items-end gap-2">
                          <form method="post" action="" class="flex flex-col items-end gap-2">
            <input type="hidden" name="action" value="sync">
            <input type="hidden" name="auth_token" value="<?= h($AUTH_TOKEN) ?>">
            <input type="hidden" name="folder" value="<?= h($p['folder']) ?>">
            <button class="px-3 py-2 rounded-xl bg-indigo-500 hover:bg-indigo-400 text-slate-950 font-semibold transition border border-indigo-400/40">
              Sincronizar
            </button>
                            <span class="text-[10px] text-slate-500">git pull --ff-only</span>
                          </form>
                          <form method="post" action="">
                            <input type="hidden" name="action" value="safe_repo">
                            <input type="hidden" name="auth_token" value="<?= h($AUTH_TOKEN) ?>">
                            <input type="hidden" name="folder" value="<?= h($p['folder']) ?>">
                            <button class="flex items-center gap-1 px-3 py-2 rounded-xl bg-slate-800 border border-white/10 hover:border-white/20 text-slate-200 text-xs transition" title="Marcar como safe.directory">
                              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                              </svg>
                              <span>Candado Git</span>
                            </button>
                          </form>
                        </div>
                      </div>
                    </div>
                  </details>
                <?php else: ?>
                  <div class="mt-4 text-xs text-slate-500">Sin repo Git detectado.</div>
                <?php endif; ?>

                  <div class="mt-5 flex items-center justify-between gap-3 text-xs text-slate-300">
                  <span><?= h(fmtDate($activityTs)) ?></span>
                  <div class="flex gap-2">
                    <a class="px-3 py-2 rounded-xl bg-slate-900/60 border border-white/10 hover:border-white/20 transition"
                      href="<?= h($p['url']) ?>" target="_blank" rel="noopener">
                      Abrir
                    </a>
                  </div>
                </div>

                <div class="mt-3 text-xs text-slate-500">
                  URL: <?= h($baseUrl . $p['url']) ?>
                </div>

                <details class="mt-4 rounded-xl bg-slate-900/50 border border-white/10 p-3 text-xs text-slate-200 project-editor">
                  <summary class="flex items-center justify-between gap-3 cursor-pointer select-none">
                    <span class="text-sm font-semibold">project.json</span>
                    <span class="text-[11px] text-slate-400">Editar y guardar</span>
                  </summary>
                  <div class="mt-3 pt-3 border-t border-white/5 space-y-2">
                    <p class="text-slate-400 text-[11px] leading-relaxed">Completa/edita los campos. Si estaba vac&iacute;o, se cargan claves por defecto.</p>
                    <form method="post" action="" class="space-y-2">
                      <input type="hidden" name="action" value="update_project">
                      <input type="hidden" name="auth_token" value="<?= h($AUTH_TOKEN) ?>">
                      <input type="hidden" name="folder" value="<?= h($p['folder']) ?>">
                      <textarea name="project_json" class="w-full h-40 rounded-lg bg-slate-950/70 border border-white/10 text-[12px] font-mono p-2 outline-none focus:ring-2 focus:ring-indigo-400/40 desc-text"><?= h($p['projectJson'] ?? '{}') ?></textarea>
                      <div class="flex justify-between items-center">
                        <span class="text-[11px] text-slate-500 hint">Claves sugeridas: title, description, tags[], url/entry/entry_url, hidden.</span>
                        <button class="px-3 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold transition border border-emerald-400/40">
                          Guardar
                        </button>
                      </div>
                    </form>
                  </div>
                </details>
              </article>
            <?php endforeach; ?>
          </div>
        <?php elseif ($section['isHidden']): ?>
          <div class="mt-4 glass border border-white/10 rounded-2xl p-5 text-slate-300">
            No hay proyectos ocultos con estos filtros.
          </div>
        <?php endif; ?>
      </div>
    <?php endforeach; ?>

    <footer class="mt-10 text-xs text-slate-500">
      Tip: agrega <span class="font-mono text-slate-300">project.json</span> o <span class="font-mono text-slate-300">project.md</span> dentro de cada proyecto para mostrar titulo/descripcion/tags.
    </footer>
  </main>
  <script>
    (function () {
      // Mostrar/Ocultar proyectos ocultos (persistente)
      const btn = document.getElementById('toggle-hidden-btn');
      const label = document.getElementById('toggle-hidden-label');
      const hiddenTotal = <?= (int)$hiddenTotal ?>;
      const panel = document.getElementById('hidden-section');
      if (btn && panel) {
        const KEY = 'dashboard_show_hidden';
        let open = localStorage.getItem(KEY) === '1';
        const render = () => {
          if (open) {
            panel.classList.remove('hidden');
            if (label) label.textContent = `Ocultar ocultos: ${hiddenTotal}`;
          } else {
            panel.classList.add('hidden');
            if (label) label.textContent = `Mostrar ocultos: ${hiddenTotal}`;
          }
        };
        btn.addEventListener('click', () => {
          open = !open;
          localStorage.setItem(KEY, open ? '1' : '0');
          render();
        });
        render();
      }

      // Modal de sincronizacion
      const syncModal = document.getElementById('sync-modal');
      const syncModalText = document.getElementById('sync-modal-text');
      const syncModalClose = document.getElementById('sync-modal-close');
      const syncForms = document.querySelectorAll('form input[name="action"][value="sync"]');
      if (syncModal && syncForms.length > 0) {
        let timeoutId = null;
        const show = () => {
          syncModal.classList.remove('hidden');
          if (syncModalText) syncModalText.textContent = 'Ejecutando git pull --ff-only en el proyecto. Por favor espera.';
          if (syncModalClose) syncModalClose.classList.add('hidden');
          timeoutId = setTimeout(() => {
            if (syncModalText) syncModalText.textContent = 'Tarda mas de lo normal. Revisa el repo (auth/permiso) o cierra este mensaje.';
            if (syncModalClose) syncModalClose.classList.remove('hidden');
          }, 20000);
        };
        syncForms.forEach((input) => {
          const form = input.closest('form');
          if (!form) return;
          form.addEventListener('submit', () => {
            show();
          });
        });
        if (syncModalClose) {
          syncModalClose.addEventListener('click', () => {
            syncModal.classList.add('hidden');
            if (timeoutId) clearTimeout(timeoutId);
          });
        }
      }

      // Tema claro/oscuro (persistente)
      const themeBtn = document.getElementById('theme-toggle-btn');
      const THEME_KEY = 'dashboard_theme';
      const doc = document.documentElement;
      const applyTheme = (t) => {
        doc.setAttribute('data-theme', t);
        if (themeBtn) themeBtn.textContent = t === 'light' ? 'Modo oscuro' : 'Modo claro';
      };
      let theme = localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark';
      applyTheme(theme);
      if (themeBtn) {
        themeBtn.addEventListener('click', () => {
          theme = theme === 'light' ? 'dark' : 'light';
          localStorage.setItem(THEME_KEY, theme);
          applyTheme(theme);
        });
      }
    })();
  </script>
</body>

</html>
