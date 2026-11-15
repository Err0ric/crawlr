// The session mode switches on the page: the first-use confirmation, the "Turn off" control, and
// keeping every copy of a switch in step. The state itself lives in modes.js, in memory only.
import { $, $$ } from "./core.js";
import { openModal, closeModal } from "./ui.js";
import { session, MODE, MODE_IDS, confirmHtml, syncSwitches, barSwitchHtml, statusHtml } from "./modes.js";

// Draws a bench's switches once, then only updates them in place, so a switch keeps focus while
// it is used. rows: [{ id, view, desc, prefix }].
export function paintBar(box, rows) {
  if (!box) return;
  if (!box.dataset.drawn) { box.innerHTML = rows.map((r) => barSwitchHtml(r.id, r.view, { prefix: r.prefix || "", desc: r.desc })).join(""); box.dataset.drawn = "1"; }
  for (const r of rows) {
    const el = box.querySelector(`[data-mode-box="${r.id}"]`); if (!el) continue;
    el.classList.toggle("off", !r.view.on);
    el.querySelector("input").checked = r.view.on;
    const d = el.querySelector(".mode-desc"), text = r.view.note || r.desc;
    if (d.textContent !== text) d.textContent = text;
  }
}
// The status line, in every place it is shown for a bench (the strip that stays in view, and its
// copy inside the Case details drawer). Each is redrawn only when it changes, and is empty, never
// hidden, when no mode is on: the strip is a live region and must stay in the page.
const lastStatus = new WeakMap();
export function paintStatus(boxes, rows, opts) {
  const html = statusHtml(rows, opts);
  for (const box of boxes) if (box && lastStatus.get(box) !== html) { box.innerHTML = html; lastStatus.set(box, html); }
}

// Asked once per page session per mode. Escape, the close button and the backdrop all leave the
// dialog without accepting, so the mode stays off.
function ask(id) {
  return ({ accept }) => openModal({
    title: MODE[id].confirmTitle,
    body: confirmHtml(id),
    actions: [{ label: "Cancel", onClick: () => closeModal() }, { label: MODE[id].confirmYes, primary: true, onClick: () => { closeModal(); accept(); } }],
  });
}
document.addEventListener("change", (e) => {
  const id = e.target?.dataset?.sessionMode;
  if (!MODE_IDS.includes(id)) return;
  session.request(id, e.target.checked === true, ask(id));
  // Whatever happened, every copy of the switch shows the state: a switch that was moved before the
  // confirmation was answered goes back to off.
  syncSwitches($$("[data-session-mode]"));
});
document.addEventListener("click", (e) => {
  const b = e.target.closest?.("[data-mode-off]");
  if (!b) return;
  const id = b.dataset.modeOff, bench = b.closest(".bench"), sheet = b.closest("#sheet");
  session.request(id, false);
  // The line this button sat on is gone. Focus goes to the switch it stood for; inside the Case
  // details drawer the page behind is inert, so it goes to the drawer's own close button; for a
  // mode of the other workbench, to the first switch of this one.
  (sheet ? sheet.querySelector("[data-close]") : bench?.querySelector(`.modes [data-session-mode="${id}"]`) || $(".bench:not([hidden]) .modes [data-session-mode]"))?.focus();
});
session.subscribe(() => syncSwitches($$("[data-session-mode]")));
