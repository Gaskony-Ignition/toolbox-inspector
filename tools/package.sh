#!/usr/bin/env bash
# Build dist/Toolbox_Inspector.zip, a project export importable on any 8.3
# gateway through Config -> Projects -> Import, for the first install or for a
# gateway without the git module.
#
#   ./tools/package.sh                 as the repo stands; the title stays "(dev)"
#   ./tools/package.sh --release [VER] stamps VER into the project title, the end
#                                      of the description and the zip's name.
#                                      VER defaults to the tag HEAD is on, so a
#                                      release is: git tag vX.Y.Z, then this.
#
# The export is the project folder zipped at its ROOT, so project.json sits at
# the top of the archive. The project IS this repo's root - the git module makes
# the repo root the project folder - so the build tooling beside it is excluded
# by name rather than by living somewhere else.
set -euo pipefail
# Repo gate (REPO-STANDARD.md). Blocking; bypass deliberately with --skip-readme-check.
if [[ " $* " != *" --skip-readme-check "* ]]; then
    _repo=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
    _gate=""; _d="$_repo"
    while [ "$_d" != / ]; do
        [ -x "$_d/modules/readme-gate.sh" ] && { _gate="$_d/modules/readme-gate.sh"; break; }
        _d=$(dirname "$_d")
    done
    if [ -n "$_gate" ]; then
        "$_gate" "$_repo" || { echo "repo gate failed: fix the README/tree or pass --skip-readme-check" >&2; exit 1; }
    else
        echo "readme-gate.sh not found above $_repo; gate skipped" >&2
    fi
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
PROJECT="."
PROJJSON="project.json"
# Outside the tree: the repo root IS the project, so a backup left here
# would be zipped into the release - which once shipped pre-stamp source.
BACKUP="$(mktemp)"

VERSION=""
if [[ "${1:-}" == "--release" ]]; then
	VERSION="${2:-}"
	if [[ -z "$VERSION" ]]; then
		VERSION="$(git describe --tags --exact-match 2>/dev/null || true)"
		[[ -n "$VERSION" ]] || {
			echo "package.sh --release: no version given and HEAD is not exactly on a tag" >&2
			exit 2; }
	fi
	VERSION="${VERSION#v}"
fi

# A release is built from committed source. Building from a reverted tree once
# shipped a release with none of its fixes.
if [[ -n "$VERSION" ]]; then
	if ! git diff --quiet HEAD; then
		echo "package.sh --release: uncommitted changes. Commit them first." >&2
		git status --short >&2
		exit 2
	fi
fi

if [[ -n "$VERSION" ]]; then
	cp "$PROJJSON" "$BACKUP"
	trap 'mv "$BACKUP" "$PROJJSON"' EXIT

	# Config -> Projects shows only the description; the Edit drawer and the
	# Perspective launch surfaces show the title. The version goes in both.
	python3 - "$PROJJSON" "$VERSION" <<'PY'
import io, json, re, sys
path, version = sys.argv[1], sys.argv[2]
doc = json.load(io.open(path, encoding='utf8'))
doc['title'] = 'Toolbox Inspector %s' % version
# Replace, never append: a suffix already there would otherwise be doubled.
doc['description'] = re.sub(r'( · (\(dev\)|v[\d.]+))+$', '', doc['description']) + ' · v%s' % version
with io.open(path, 'w', encoding='utf8') as handle:
	# The gateway's own format: no trailing newline, non-ASCII raw.
	json.dump(doc, handle, indent=2, ensure_ascii=False)
PY
	grep -q "\"title\": \"Toolbox Inspector $VERSION\"" "$PROJJSON"
	grep -q "v$VERSION\"" "$PROJJSON"
fi

# Accessibility gate (a11y.json, REPO-STANDARD.md). Blocking; bypass deliberately
# with --skip-a11y-check. The gate checks what is DEPLOYED, so this pushes the
# current tree to module-testing (this host's local docker gateway named in
# a11y.json) and scans it first, same as any other file-based deploy there.
if [[ " $* " != *" --skip-a11y-check "* ]]; then
	_a11y_gate=""; _d="$HERE"
	while [ "$_d" != / ]; do
		[ -x "$_d/modules/a11y-gate.sh" ] && { _a11y_gate="$_d/modules/a11y-gate.sh"; break; }
		_d=$(dirname "$_d")
	done
	if [ -n "$_a11y_gate" ]; then
		CONTAINER="ignition-module-testing"
		REMOTE_DIR="/usr/local/bin/ignition/data/projects/Toolbox_Inspector"
		docker exec "$CONTAINER" mkdir -p "$REMOTE_DIR"
		tar -cf - --exclude='.git' --exclude='.gitignore' --exclude='.gitmodules' \
		    --exclude='README.md' --exclude='tools' \
		    --exclude='docs' --exclude='a11y.json' --exclude='.github' --exclude='dist' --exclude='__pycache__' . \
			| docker exec -i "$CONTAINER" tar -xf - -C "$REMOTE_DIR"
		node /Home-Claude/ignition-claude-toolkit/plugins/ignition/skills/scan/tool/scan.js --gateway module-testing >/dev/null
		sleep 3
		"$_a11y_gate" "$HERE" || { echo "a11y gate failed: fix the findings, or record a reasoned exception in a11y.json (--skip-a11y-check to bypass)" >&2; exit 1; }
	else
		echo "a11y-gate.sh not found above $HERE; gate skipped" >&2
	fi
fi

# Lint gate (REPO-STANDARD.md). Blocking; bypass deliberately with --skip-lint-check.
if [[ " $* " != *" --skip-lint-check "* ]]; then
	_lint_gate=""; _d="$HERE"
	while [ "$_d" != / ]; do
		[ -x "$_d/modules/lint-gate.sh" ] && { _lint_gate="$_d/modules/lint-gate.sh"; break; }
		_d=$(dirname "$_d")
	done
	if [ -n "$_lint_gate" ]; then
		"$_lint_gate" "$HERE" || { echo "lint gate failed: fix the errors, or record a reasoned exception in lint.json (--skip-lint-check to bypass)" >&2; exit 1; }
	else
		echo "lint-gate.sh not found above $HERE; gate skipped" >&2
	fi
fi

mkdir -p dist
ZIPNAME="Toolbox_Inspector${VERSION:+-$VERSION}.zip"
rm -f "dist/$ZIPNAME"

# No global-props resource is carried, so the importing gateway keeps its own
# settings.
EXCLUDE=( -x '.git/*' '.gitignore' '.gitmodules' 'README.md' 'a11y.json'
          'tools/*' 'docs/*' 'dist/*' '.github/*' '*__pycache__*' )
( cd "$HERE" && zip -qr "$HERE/dist/$ZIPNAME" . "${EXCLUDE[@]}" )

echo "dist/$ZIPNAME ($(du -h "dist/$ZIPNAME" | cut -f1), $(unzip -l "dist/$ZIPNAME" | tail -1 | awk '{print $2}') files)"
