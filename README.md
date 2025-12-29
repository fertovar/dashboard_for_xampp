# Dashboard de proyectos XAMPP

Panel local para listar proyectos en `htdocs`, ver metadatos, revisar estado Git y operar sobre ellos (sincronizar, marcar safe.directory, clonar desde GitHub y editar `project.json`).

## Requisitos mínimos
- PHP (XAMPP) con `exec` habilitado.
- Git instalado en el servidor web. Si no está en `PATH`, configura la ruta en `index.php` (`$GIT_BIN_OVERRIDE`) o variable de entorno `GIT_BIN`.
- Usuario del servicio web con permisos sobre los repos. El dashboard añade `-c safe.directory=<ruta>` y ofrece un botón de candado para marcar repos como seguros.
- Opcional: GitHub CLI (`gh`) y token `GITHUB_TOKEN`/`GH_TOKEN` si quieres listar/clonar repos desde GitHub.

## Configuración rápida (variables en `index.php`)
- Autenticación: `$LOGIN_USER`, `$LOGIN_PASS`.
- Git:
  - `$GIT_BIN_OVERRIDE = 'C:\\Program Files\\Git\\cmd\\git.exe';` si Git no está en PATH.
  - `$GIT_AUTO_FETCH = false;` (recomendado). Pon `true` si quieres `git fetch` automático en cada carga.
  - Safe directory: cada comando git lleva `-c safe.directory="<ruta>"` y se intenta agregar globalmente una sola vez por repo.
- GitHub (opcional): `$ENABLE_GH_LIST = false;` (por defecto). Pon `true` para usar `gh`/API y poblar el combo de clonado.

## Controles en la interfaz
- **Sincronizar**: ejecuta `git pull --ff-only` (sin prompts interactivos; usa `GIT_TERMINAL_PROMPT=0`).
- **Candado Git**: agrega `safe.directory` global para ese repo y evita “dubious ownership”.
- **Check entorno** (header): muestra versión de git/gh y si el token GitHub está presente.
- **Clonar desde GitHub**: en panel plegable; requiere `gh` logueado o token en entorno si habilitaste `$ENABLE_GH_LIST`.
- **Editor project.json**: abre/edita/guarda el archivo por proyecto.
- **Modal de sincronización**: aparece mientras corre git; a los 20s muestra aviso y botón para cerrar si tarda más de lo normal.

## Uso rápido
1) Inicia sesión.
2) Pulsa **Check entorno** para ver si git/gh/token están disponibles.
3) Para un repo existente:
   - Si ves “dubious ownership”, pulsa **Candado Git** y luego **Sincronizar**.
   - Si el remote es HTTPS y requiere token, asegúrate de que el usuario del servicio tenga credenciales (ver sección Git/Token).
4) Para clonar: abre “Clonar desde GitHub”, elige repo (si `$ENABLE_GH_LIST = true`) o pega URL, opcional carpeta destino, y pulsa **Clonar**.
5) Edita `project.json` desde la tarjeta del proyecto si necesitas ajustar título/desc/tags/url/hidden.

## Pruebas de verificación
1) Git disponible: `"<ruta a git.exe>" --version` (o usa `$GIT_BIN_OVERRIDE`). Esperado: versión sin error.
2) Sincronizar: pulsa **Sincronizar**; esperado: modal breve y banner de éxito. Si falla, revisa mensaje (auth, safe.directory, upstream).
3) Clonado GitHub (si `$ENABLE_GH_LIST = true`): `gh auth status` en el usuario del servicio; esperado: autenticado. Dropdown debe listar repos.
4) Guardado `project.json`: edita y guarda; esperado: banner de éxito y archivo actualizado.
5) Check entorno: botón en header; esperado: banner con versiones y token detectado/no detectado.

## Git y credenciales (usuario del servicio, p.ej. SYSTEM)
- Para repos HTTPS con token:
  - Mapea token a GitHub:  
    `git config --global url."https://<TOKEN>:x-oauth-basic@github.com/".insteadOf "https://github.com/"`
  - Verifica: `git -C C:\xampp\htdocs\<repo> ls-remote origin`
- Para marcar repos como seguros (evitar “dubious ownership”):
  - Un repo: `git config --global --add safe.directory "C:/xampp/htdocs/<repo>"`
  - Varios repos (PowerShell):  
    ```powershell
    $repos = Get-ChildItem -Path C:\xampp\htdocs -Directory -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { Test-Path "$($_.FullName)\.git" }
    foreach ($r in $repos) { git config --global --add safe.directory "$($r.FullName)" }
    ```
  - Limpiar duplicados:  
    `git config --global --unset-all safe.directory`  
    y vuelve a agregar solo los necesarios.
- Evitar pager en config: `git --no-pager config --show-origin --get-all safe.directory` o `set GIT_PAGER=cat`.
- Sin prompts de credenciales: los comandos git se ejecutan con `GIT_TERMINAL_PROMPT=0`; si faltan credenciales, fallan rápido en lugar de colgarse.

## Notas
- No expongas este dashboard a internet sin protección (credenciales fuertes, red restringida).
- El orden de la lista siempre es “más reciente” (actividad git/mtime) y coloca proyectos sin repo al final.
- Si usas `$GIT_AUTO_FETCH = true`, puede tardar si hay muchos repos. Manténlo en `false` y usa **Sincronizar** cuando lo necesites.
