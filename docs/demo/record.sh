#!/usr/bin/env bash
# Records docs/demo.gif: the real dnstui, in a real Ghostty window, on Hyprland.
#
# Needs: ghostty, ffmpeg (x11grab), hyprland (hyprctl), xprop, python3, cargo.
# Ghostty runs under XWayland so ffmpeg can capture just that window; nothing
# else on the screen is recorded. Your own Ghostty config is used (font, theme)
# apart from the overrides below, which make the capture opaque and a fixed size.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
ffpid=""
cleanup() {
    # The window closes by itself when the driver exits; this is for failures.
    [ ! -s "$work/pid" ] || kill "$(cat "$work/pid")" 2>/dev/null || true
    [ -z "$ffpid" ] || kill "$ffpid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

COLS=${COLS:-120}
ROWS=${ROWS:-30}
FONT_SIZE=${FONT_SIZE:-14}
FPS=${FPS:-15}
TRIM_HEAD=${TRIM_HEAD:-1.0}   # seconds of blank start-up to drop
OUT=${OUT:-$repo/docs/demo.gif}

cargo build --release --manifest-path "$repo/Cargo.toml" >&2

# The demo's own config: Catppuccin Frappé, matching the terminal's theme.
mkdir -p "$work/cfg/dnstui"
cat > "$work/cfg/dnstui/config.yml" <<'YML'
theme: catppuccin-frappe
transparent_background: true
YML

# Floating, so the window doesn't re-tile whatever else is on the workspace.
# (Hyprland 0.5x takes Lua here: hl.dsp.exec_cmd(command, window rules).)
cmd="env GDK_BACKEND=x11 ghostty --class=dnstui.demo --gtk-single-instance=false \
--window-decoration=none --background-opacity=1 --background-blur=0 \
--font-size=$FONT_SIZE --window-width=$COLS --window-height=$ROWS \
--confirm-close-surface=false \
-e python3 -I $here/driver.py $repo/target/release/dnstui $work/cfg $work/go $work/done $work/stop $work/pid"
hyprctl dispatch "hl.dsp.exec_cmd(\"$cmd\", {float=true, move=\"120 70\"})" >/dev/null

xid=""
for _ in $(seq 100); do
    for id in $(xprop -root -notype _NET_CLIENT_LIST 2>/dev/null | grep -o '0x[0-9a-f]*'); do
        if xprop -id "$id" WM_CLASS 2>/dev/null | grep -q dnstui; then xid=$id; fi
    done
    [ -n "$xid" ] && break
    sleep 0.1
done
[ -n "$xid" ] || { echo "the Ghostty window never appeared" >&2; exit 1; }
sleep 1.5   # let the window reach its final size

ffmpeg -hide_banner -loglevel error -y -f x11grab -window_id "$xid" -framerate 30 \
    -draw_mouse 0 -i :0 -c:v libx264 -preset ultrafast -crf 0 -pix_fmt yuv444p \
    "$work/capture.mkv" &
ffpid=$!
sleep 0.7
touch "$work/go"

for _ in $(seq 600); do [ -e "$work/done" ] && break; sleep 0.2; done
[ -e "$work/done" ] || { echo "the demo did not finish" >&2; exit 1; }
sleep 0.5
kill -INT "$ffpid"; wait "$ffpid" || true
ffpid=""
touch "$work/stop"
[ -s "$work/capture.mkv" ] || { echo "nothing was captured" >&2; exit 1; }

# One shared palette for the whole run keeps the text edges clean and stable.
ffmpeg -hide_banner -loglevel error -y -ss "$TRIM_HEAD" -i "$work/capture.mkv" -vf \
    "fps=$FPS,split[a][b];[a]palettegen=max_colors=256:stats_mode=full[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
    "$OUT"
ls -la "$OUT" >&2
