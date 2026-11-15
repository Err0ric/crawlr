// The session mode switches on the page: the first-use confirmation, the "Turn off" control, and
// keeping every copy of a switch in step. The state itself lives in modes.js, in memory only.
import { $, $$ } from "./core.js";
import { openModal, closeModal } from "./ui.js";
import { session, MODE, MODE_IDS, confirmHtml, syncSwitches, barSwitchHtml, statusHtml } from "./modes.js";

// Draws a bench's switches once, then only updates them in place, so a switch keeps focus while
// it is used. rows: [{ id, view, desc, prefix }]. The status line is redrawn only when it changes.
const lastStatus = new WeakMap();
export function paintBar(box, statusBox, rows) {
  if (!box || !statusBox) return;
  if (!box.dataset.drawn) { box.innerHTML = rows.map((r) => barSwitchHtml(r.id, r.view, { prefix: r.prefix || "", desc: r.desc })).join(""); box.dataset.drawn = "1"; }
  for (const r of rows) {
    const el = box.querySelector(`[data-mode-box="${r.id}"]`); if (!el) continue;
    el.classList.toggle("off", !r.view.on);
    el.querySelector("input").checked = r.view.on;
    const d = el.querySelector(".mode-desc"), text = r.view.note || r.desc;
    if (d.textContent !== text) d.textContent = text;
  }
  const html = statusHtml(rows);
  if (lastStatus.get(statusBox) !== html) { statusBox.innerHTML = html; lastStatus.set(statusBox, html); }
  statusBox.hidden = !html;
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
  const id = b.dataset.modeOff, bench = b.closest(".bench");
  session.request(id, false);
  // The line this button sat on is gone: focus goes to the switch it stood for.
  (bench?.querySelector(`.modes [data-session-mode="${id}"]`) || $(".bench:not([hidden]) .modes [data-session-mode]"))?.focus();
});
session.subscribe(() => syncSwitches($$("[data-session-mode]")));
