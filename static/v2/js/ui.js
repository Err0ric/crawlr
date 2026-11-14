// Modal + drawer primitives. One overlay root, one open thing at a time.
// Both are real dialogs: focus moves in, Tab is trapped, Escape closes (unless the
// dialog is `required`), the page behind is inert, and focus returns to the opener.
import { $, h, raw, esc } from "./core.js";

const root = () => $("#overlays");
const FOCUSABLE = "a[href],button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex='-1'])";
const openers = [];   // stack: where focus goes back to

function setPageInert(on) {
  for (const el of document.body.children) {
    if (el.id === "overlays" || el.id === "toast") continue;
    if (on) el.setAttribute("inert", ""); else el.removeAttribute("inert");
  }
}
function syncInert() { setPageInert(!!root().children.length); }

function trapFocus(container, onEscape) {
  container.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.stopPropagation(); onEscape?.(); return; }
    if (e.key !== "Tab") return;
    const els = [...container.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null);
    if (!els.length) { e.preventDefault(); return; }
    const first = els[0], last = els[els.length - 1];
    if (e.shiftKey && (document.activeElement === first || !container.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
}
function restoreFocus() {
  const el = openers.pop();
  if (el && document.contains(el)) el.focus?.();
}

// required: the dialog can only be left through one of its actions (used by the consent gate).
export function openModal({ title, body, actions = [], wide = false, required = false, focus }) {
  closeModal({ restore: false });
  openers.push(document.activeElement);
  // A dialog opened from the phone drawer sits over it: the drawer stays, goes inert, and gets
  // focus back on the control that opened the dialog.
  $("#sheet")?.setAttribute("inert", "");
  const el = document.createElement("div");
  el.className = "modal-backdrop"; el.id = "modal";
  el.innerHTML = h`
    <div class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-labelledby="modalTitle" aria-describedby="modalBody">
      <div class="modal-head"><h2 id="modalTitle">${title}</h2>${required ? "" : raw('<button class="btn btn-ghost btn-icon" type="button" data-close aria-label="Close dialog">✕</button>')}</div>
      <div class="modal-body" id="modalBody">${raw(body)}</div>
      ${actions.length ? raw(`<div class="modal-foot">${actions.map((a, i) => `<button class="btn ${a.primary ? "btn-primary" : ""}" type="button" data-action="${i}"${a.disabled ? " disabled" : ""}>${esc(a.label)}</button>`).join("")}</div>`) : ""}
    </div>`;
  el.addEventListener("click", (e) => {
    if (!required && (e.target === el || e.target.closest("[data-close]"))) { closeModal(); return; }
    const a = e.target.closest("[data-action]"); if (a) actions[+a.dataset.action].onClick?.(el);
  });
  // A click on the backdrop must not pull keyboard focus out of the dialog.
  el.addEventListener("mousedown", (e) => { if (e.target === el) e.preventDefault(); });
  trapFocus(el, required ? null : closeModal);
  root().appendChild(el);
  syncInert();
  // A long dialog scrolls inside its body. Make that region reachable from the keyboard.
  const bodyEl = el.querySelector(".modal-body");
  if (bodyEl.scrollHeight > bodyEl.clientHeight + 1) { bodyEl.tabIndex = 0; bodyEl.setAttribute("role", "group"); bodyEl.setAttribute("aria-label", `${title}, scrollable`); }
  (el.querySelector(focus || "input,textarea,button.btn-primary:not([disabled])") || el.querySelector(FOCUSABLE))?.focus();
  return el;
}
export function closeModal({ restore = true } = {}) {
  const m = $("#modal"); if (!m) return;
  m.remove(); syncInert();
  $("#sheet")?.removeAttribute("inert");
  if (restore) restoreFocus(); else openers.pop();
}

export function openDrawer({ title, body }) {
  closeDrawer({ restore: false }); closeModal({ restore: false }); closeSheet({ restore: false });
  openers.push(document.activeElement);
  const bd = document.createElement("div"); bd.className = "drawer-backdrop"; bd.id = "drawerBackdrop";
  const el = document.createElement("div"); el.className = "drawer"; el.id = "drawer";
  el.setAttribute("role", "dialog"); el.setAttribute("aria-modal", "true"); el.setAttribute("aria-labelledby", "drawerTitle");
  el.innerHTML = h`<div class="drawer-head"><h2 id="drawerTitle">${title}</h2><button class="btn btn-ghost btn-icon" type="button" data-close aria-label="Close ${title}">✕</button></div><div class="drawer-body">${raw(body)}</div>`;
  bd.addEventListener("click", () => closeDrawer());
  el.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) closeDrawer(); });
  trapFocus(el, closeDrawer);
  root().append(bd, el);
  syncInert();
  el.querySelector("[data-close]").focus();
  return el;
}
// A sheet shows an element that already lives in the page (the case summary column, on a phone)
// as a dialog: the element is moved into the overlay root and put back where it was on close, so
// its fields, listeners and ids are untouched. Focus moves in, Tab is trapped, Escape closes, the
// page behind is inert and focus returns to the opener.
let sheetHome = null;
export function openSheet({ title, el }) {
  closeSheet({ restore: false }); closeDrawer({ restore: false }); closeModal({ restore: false });
  openers.push(document.activeElement);
  document.documentElement.classList.add("sheet-open");      // the page behind does not scroll
  sheetHome = document.createComment("sheet"); el.before(sheetHome);
  const bd = document.createElement("div"); bd.className = "sheet-backdrop"; bd.id = "sheetBackdrop";
  const box = document.createElement("div"); box.className = "sheet"; box.id = "sheet";
  box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "sheetTitle");
  box.innerHTML = h`<div class="sheet-head"><h2 id="sheetTitle">${title}</h2><button class="btn btn-ghost btn-icon" type="button" data-close aria-label="Close ${title}">✕</button></div><div class="sheet-body"></div>`;
  box.querySelector(".sheet-body").appendChild(el);
  bd.addEventListener("click", () => closeSheet());
  box.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) closeSheet(); });
  trapFocus(box, closeSheet);
  root().append(bd, box);
  syncInert();
  box.querySelector("[data-close]").focus();
  return box;
}
export function closeSheet({ restore = true } = {}) {
  const box = $("#sheet"); if (!box) return;
  const el = box.querySelector(".sheet-body").firstElementChild;
  if (el && sheetHome?.parentNode) sheetHome.replaceWith(el);
  sheetHome = null;
  box.remove(); $("#sheetBackdrop")?.remove(); syncInert();
  document.documentElement.classList.remove("sheet-open");
  if (restore) restoreFocus(); else openers.pop();
}

export function closeDrawer({ restore = true } = {}) {
  const d = $("#drawer"); if (!d) return;
  d.remove(); $("#drawerBackdrop")?.remove(); syncInert();
  if (restore) restoreFocus(); else openers.pop();
}
