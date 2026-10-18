// Modal + drawer primitives. One overlay root, one open thing at a time.
import { $, h, raw, esc } from "./core.js";

const root = () => $("#overlays");
let lastFocus = null;

function trapFocus(container) {
  const f = () => [...container.querySelectorAll("a[href],button:not([disabled]),input,textarea,select,[tabindex]:not([tabindex='-1'])")];
  container.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.stopPropagation(); closeModal(); closeDrawer(); }
    if (e.key !== "Tab") return;
    const els = f(); if (!els.length) return;
    const first = els[0], last = els[els.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
}

export function openModal({ title, body, actions = [], wide = false }) {
  closeModal();
  lastFocus = document.activeElement;
  const el = document.createElement("div");
  el.className = "modal-backdrop"; el.id = "modal";
  el.innerHTML = h`
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle" ${wide ? raw('style="width:min(100%,760px)"') : ""}>
      <div class="modal-head"><h2 id="modalTitle">${title}</h2><button class="btn btn-ghost btn-sm" type="button" data-close aria-label="Close">✕</button></div>
      <div class="modal-body">${raw(body)}</div>
      ${actions.length ? raw(`<div class="modal-foot">${actions.map((a, i) => `<button class="btn ${a.primary ? "btn-primary" : ""}" type="button" data-action="${i}">${esc(a.label)}</button>`).join("")}</div>`) : ""}
    </div>`;
  el.addEventListener("click", (e) => {
    if (e.target === el || e.target.closest("[data-close]")) closeModal();
    const a = e.target.closest("[data-action]"); if (a) actions[+a.dataset.action].onClick?.(el);
  });
  trapFocus(el);
  root().appendChild(el);
  (el.querySelector("input,textarea,button.btn-primary") || el.querySelector("button")).focus();
  return el;
}
export function closeModal() { $("#modal")?.remove(); lastFocus?.focus?.(); }

export function openDrawer({ title, body }) {
  closeDrawer(); closeModal();
  lastFocus = document.activeElement;
  const bd = document.createElement("div"); bd.className = "drawer-backdrop"; bd.id = "drawerBackdrop";
  const el = document.createElement("aside"); el.className = "drawer"; el.id = "drawer"; el.setAttribute("role", "dialog"); el.setAttribute("aria-label", title);
  el.innerHTML = h`<div class="drawer-head"><h2>${title}</h2><button class="btn btn-ghost btn-sm" type="button" data-close aria-label="Close">✕</button></div><div class="drawer-body">${raw(body)}</div>`;
  bd.addEventListener("click", closeDrawer);
  el.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) closeDrawer(); });
  trapFocus(el);
  root().append(bd, el);
  el.querySelector("button,input").focus();
  return el;
}
export function closeDrawer() { $("#drawer")?.remove(); $("#drawerBackdrop")?.remove(); }
