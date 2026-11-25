# M1 workbench sizing candidate

Vanilla JS/CSS only. No frontend package install or bundle. Go `embed_assets.go`
embeds `web/*` on normal rebuild; native cmd is currently Windows-only.

From repository root:

```sh
node --check studio/web/workbench-layout.js
node --test studio/web-tests/workbench-layout.test.cjs
(cd studio && go test -race .)
python3 -m http.server 17873 --bind 127.0.0.1 --directory studio/web
# http://127.0.0.1:17873/?demo=1&autoload=1
```

Static demo uses pre-existing synthetic data, no backend/device/transport. Plugin
center's real kernel API is outside the static demo. Do not remove `demo=1` and
assume this static server is a Go backend. Full Go regression additionally needs
the existing exact-locked Cordis host test environment (`PKTPATH_TEST_CORDIS_HOST`);
a missing environment is not proof of lifecycle tests passing.

M1 only: rail width (240–560px), two-chart width split (280px minimum outer
panel width each), each chart height (240–1200px), table height (280–1600px),
reset/default restoration. Narrow workbench (<680px) stacks the rail; a chart
row <570px stacks the charts and disables its width handle. Content scrolls
inside the panels; SVG's existing natural geometry/minimum widths are retained.

Drag separator/bottom grips. Focus a grip: relevant arrow keys change 16px
(or 2% for charts); Shift makes a larger step, Home/End clamp, Enter or double
click resets that dimension. Escape, pointer cancellation/lost capture, blur
or hiding cancels an in-progress drag. Reset clears only the new dimension
key, not theme, rail-fold setting or backend config. Preferences are stored
on successful gesture/key actions, not on responsive reflow. Storage is only
within this browser/origin, not across different ephemeral server ports.

Node tests use an explicit non-rendering DOM/event/geometry model, including a
VM of the browser-entry path. These are NOT real mouse/touch/keyboard rendering
checks. M1 acceptance requires independent real-browser dragging + chart
repaint, restored layout and reset checks. Touch/pen event handling has model
coverage only; no touch hardware or Windows/WebView runtime was tested here.
No reorder, maximize, arbitrary floating windows, plugin/API/default changes.
