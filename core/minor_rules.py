"""
The engine for the minor guard's rules.

Every pattern and threshold lives in one file, static/v2/data/minor-rules.json, which the page
loads too (static/v2/js/minorscan.js is the same engine in JavaScript). Nothing here is a rule:
this module reads the file, checks it, and applies it. tests/test_minor_parity.py runs the same
fixtures through both engines and fails on any difference.

Three questions are answered:

  handle_token(handle)             "age" or "word" when the handle itself carries an explicit
                                   age under 18 or one of three words, else None
  soft_birth_year(handle, today)   a four-digit year in the handle that would make the person
                                   6 to 18 today, else None. It never blocks on its own
  soft_bare_years(handle)          digits then "yrs" or "years" with no "old" (10yrs_exp,
                                   12years_sober) when the number is 8 to 17, else None. The
                                   second soft signal: it never blocks on its own either
  scan(profiles, handle, today)    reads the names and bios of the profiles found for a handle
                                   and returns the signals that suggest a minor

Text is normalised before any pattern sees it (see `normalize` in the rules file): ASCII only,
lowercase, one space for any run of whitespace, "|" for a line break or a bullet. Both engines
work on code points, so a snippet is the same string on both sides.

If the file is missing or does not validate, ENGINE is None and LOAD_ERROR says why. Callers
treat that as "refuse": see core.adult_guard.
"""

import json
import re
import unicodedata
from datetime import date
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parent.parent / "static" / "v2" / "data" / "minor-rules.json"
VERSION = 1
SOURCE_MAX = 80
URL_MAX = 600
FIELD_MAX = 40


class RulesError(ValueError):
    """The rules file is missing a part, has the wrong version or holds a pattern that does not compile."""


def _ymd(today) -> tuple[int, int, int]:
    if isinstance(today, date):
        return today.year, today.month, today.day
    y, m, d = today
    return int(y), int(m), int(d)


class Engine:
    def __init__(self, doc: dict):
        if not isinstance(doc, dict) or doc.get("version") != VERSION:
            raise RulesError("version")
        try:
            self.adult_age = int(doc["adult_age"])
            n = doc["normalize"]
            self._ws = [(int(a), int(b)) for a, b in n["whitespace"]]
            self._breaks = {int(x) for x in n["line_break"]}
            self._drop = {int(x) for x in n["drop"]}
            self._map = {str(k): str(v) for k, v in n["map"].items()}
            self._sep_ranges = [(int(a), int(b)) for a, b in n["separator_ranges"]]
            self._sep = str(n["separator"])
            self._other = str(n["other"])
            self._max_chars = int(n["max_chars"])
            self._nfkc = n.get("nfkc") is True
            src = doc["sources"]
            self.profile_readers = [(str(a), str(b)) for a, b in src["profile_readers"]]
            self.text_order = [(str(a), str(b)) for a, b in src["text_order"]]
            self.reported_when_failed = [(str(a), str(b), str(c)) for a, b, c in src["reported_when_failed"]]
            self._delims = set(str(doc["clause"]["delimiters"]))
            self._period_word = int(doc["clause"]["period_needs_word"])
            self.snippet_max = int(doc["snippet_max"])
            self.signals_max = int(doc["signals_max"])
            self._macros = {str(k): str(v) for k, v in doc["macros"].items()}
            h = doc["handle"]
            self._strip = str(h["strip"])
            self._handle_seps = set(str(h["separators"]))
            self._age_min, self._age_max = int(h["age"]["min"]), int(h["age"]["max"])
            self._age_rx = [self._rx(p) for p in h["age"]["patterns"].values()]
            self._age_not_after = self._rx(h["age"]["not_after"])
            self._words_rx = self._rx(h["words"]["pattern"])
            self._leet = [{str(k): str(v) for k, v in t.items()} for t in h["words"]["leet"]]
            self._soft_rx = self._rx(h["soft_year"]["pattern"])
            self._soft_min, self._soft_max = int(h["soft_year"]["min_age"]), int(h["soft_year"]["max_age"])
            self._years_rx = self._rx(h["soft_years"]["pattern"])
            self._years_min, self._years_max = int(h["soft_years"]["min"]), int(h["soft_years"]["max"])
            c = doc["content"]
            self._birth = c["birth"]
            self._birth_rx = self._rx(self._birth["field_pattern"])
            self._agefield_rx = self._rx(self._birth["age_field_pattern"])
            self._class = c["class_year"]
            for key in ("min_age", "year_only_max_age", "two_digit_base", "age_min", "age_max"):
                int(self._birth[key])
            for key in ("max_ahead", "strong_ahead", "this_year_until_month", "two_digit_base"):
                int(self._class[key])
            self._ctx = {name: (self._rx(x["pattern"]), x.get("cased") is True) for name, x in c["contexts"].items()}
            self._rules = []
            for r in c["rules"]:
                if r["kind"] not in ("age", "school", "birth") or r["strength"] not in ("strong", "weak", "by_value"):
                    raise RulesError(f"rule {r.get('id')}")
                if r["value"] not in ("none", "age", "birth_year", "class_year"):
                    raise RulesError(f"rule {r.get('id')}")
                for key in ("unless", "needs", "strong_if"):
                    for name, scope in r.get(key, []):
                        if name not in self._ctx or scope not in ("clause", "text"):
                            raise RulesError(f"rule {r.get('id')}")
                self._rules.append({**r, "rx": self._rx(r["pattern"])})
        except RulesError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError, re.error) as e:
            raise RulesError(type(e).__name__) from e

    # ---- patterns --------------------------------------------------------------------
    def _rx(self, pattern: str) -> re.Pattern:
        text = str(pattern)
        for _ in range(5):
            for name, value in self._macros.items():
                text = text.replace("{{" + name + "}}", value)
        if "{{" in text:
            raise RulesError("macro")
        return re.compile(text, re.ASCII)

    # ---- normalising -----------------------------------------------------------------
    def normalize(self, text) -> tuple[list[str], str, str]:
        """(the kept characters, the lowercase match string, the same with capitals kept).
        All three have one entry per kept code point."""
        orig: list[str] = []
        low: list[str] = []
        cased: list[str] = []
        pending = brk = False
        raw = "".join(list(str(text if text is not None else ""))[: self._max_chars])
        if self._nfkc:
            # Fancy digits and letters (fullwidth, mathematical) become plain ones, on both sides.
            raw = unicodedata.normalize("NFKC", raw)
        for ch in list(raw)[: self._max_chars]:
            cp = ord(ch)
            if cp in self._drop:
                continue
            if any(a <= cp <= b for a, b in self._ws):
                pending = True
                brk = brk or cp in self._breaks
                continue
            if pending and orig:
                orig.append(" ")
                low.append(self._sep if brk else " ")
                cased.append(self._sep if brk else " ")
            pending = brk = False
            if cp < 128:
                if cp < 32 or cp == 127:
                    lo = up = self._other
                elif 65 <= cp <= 90:
                    lo, up = chr(cp + 32), ch
                else:
                    lo = up = ch
            elif ch in self._map:
                lo = up = self._map[ch]
            elif any(a <= cp <= b for a, b in self._sep_ranges):
                lo = up = self._sep
            else:
                lo = up = self._other
            orig.append(ch)
            low.append(lo)
            cased.append(up)
        return orig, "".join(low), "".join(cased)

    # ---- the handle ------------------------------------------------------------------
    def _handle(self, handle) -> str:
        return self.normalize(handle)[1].lstrip(self._strip)

    def handle_token(self, handle) -> str | None:
        raw = self._handle(handle)
        if not raw:
            return None
        for rx in self._age_rx:
            for m in rx.finditer(raw):
                # An age about someone else (mom_of_16yo) is not the handle owner's.
                if self._age_min <= int(m.group(1)) <= self._age_max and not self._age_not_after.search(raw[: m.start()]):
                    return "age"
        joined = "".join(ch for ch in raw if ch not in self._handle_seps)
        for table in [None, *self._leet]:
            text = joined if table is None else "".join(table.get(ch, ch) for ch in joined)
            if self._words_rx.search(text):
                return "word"
        return None

    def soft_birth_year(self, handle, today) -> int | None:
        year = _ymd(today)[0]
        for m in self._soft_rx.finditer(self._handle(handle)):
            y = int(m.group(1))
            if self._soft_min <= year - y <= self._soft_max:
                return y
        return None

    def soft_bare_years(self, handle) -> int | None:
        for m in self._years_rx.finditer(self._handle(handle)):
            if self._years_min <= int(m.group(1)) <= self._years_max:
                return int(m.group(1))
        return None

    # ---- profile text ----------------------------------------------------------------
    def _clause(self, delims: list[int], s: int, e: int, n: int) -> tuple[int, int]:
        a, b = 0, n
        for d in delims:
            if d < s:
                a = d + 1
            elif d >= e:
                b = d
                break
        return a, b

    def _delims_of(self, low: str) -> list[int]:
        out = []
        w = self._period_word
        for i, ch in enumerate(low):
            if ch in self._delims:
                out.append(i)
            elif ch == "." and (i + 1 == len(low) or low[i + 1] == " ") and i >= w and all(c.isascii() and c.isalnum() for c in low[i - w:i]):
                out.append(i)
        return out

    def _snippet(self, orig: list[str], s: int, e: int) -> str:
        n, mx = len(orig), self.snippet_max
        if e - s >= mx:
            a, b = s, s + mx
        else:
            pad = (mx - (e - s)) // 2
            a = max(0, s - pad)
            b = min(n, a + mx)
            a = max(0, b - mx)
            if a > 0 and orig[a - 1] != " ":
                j = a
                while j < s and orig[j] != " ":
                    j += 1
                if j < s:
                    a = j + 1
            if b < n and orig[b] != " ":
                j = b - 1
                while j >= e and orig[j] != " ":
                    j -= 1
                if j >= e:
                    b = j
        return "".join(orig[a:b]).strip(" ")

    def _ctx_hit(self, pairs, low: str, cased: str, span: tuple[int, int]) -> bool:
        for name, scope in pairs or []:
            rx, is_cased = self._ctx[name]
            text = cased if is_cased else low
            if rx.search(text if scope == "text" else text[span[0]:span[1]]):
                return True
        return False

    def _year(self, digits: str, base: int, year: int, future: bool) -> int:
        y = int(digits)
        if len(digits) == 2:
            y += base
            if not future and y > year:
                y -= 100
        return y

    def _field_signals(self, rule_fields: str, text, today) -> list[dict]:
        orig, low, cased = self.normalize(text)
        if not low:
            return []
        year, month, _day = today
        delims = self._delims_of(low)
        out = []
        for r in self._rules:
            if rule_fields not in r["fields"]:
                continue
            for m in r["rx"].finditer(low):
                groups = [g for g in m.groups() if g is not None]
                strength = r["strength"]
                value = r["value"]
                if value == "age":
                    if not groups or not (int(r["min"]) <= int(groups[0]) <= int(r["max"])):
                        continue
                elif value == "birth_year":
                    g = m.group(int(r["year_group"])) if r.get("year_group") else (groups[0] if groups else None)
                    if g is None:
                        continue
                    age = year - self._year(g, int(self._birth["two_digit_base"]), year, False)
                    if not (int(self._birth["min_age"]) <= age <= int(self._birth["year_only_max_age"])):
                        continue
                elif value == "class_year":
                    if not groups:
                        continue
                    ahead = self._year(groups[0], int(self._class["two_digit_base"]), year, True) - year
                    if ahead < 0 or ahead > int(self._class["max_ahead"]):
                        continue
                    if ahead == 0 and month > int(self._class["this_year_until_month"]):
                        continue
                span = self._clause(delims, m.start(), m.end(), len(low))
                if r.get("needs") and not self._ctx_hit(r["needs"], low, cased, span):
                    continue
                if self._ctx_hit(r.get("unless"), low, cased, span):
                    continue
                if strength == "by_value":
                    strong = ahead >= int(self._class["strong_ahead"]) or self._ctx_hit(r.get("strong_if"), low, cased, span)
                    strength = "strong" if strong else "weak"
                out.append({"strength": strength, "kind": r["kind"], "rule": r["id"], "snippet": self._snippet(orig, m.start(), m.end())})
        return out

    def _birth_fields(self, profile: dict, today) -> list[dict]:
        year, month, day = today
        out = []
        b = self._birth
        for key in b["field_keys"]:
            orig, low, _ = self.normalize(profile.get(key))
            m = self._birth_rx.search(low)
            if not m:
                continue
            y = int(m.group(1))
            if m.group(2) and m.group(3):
                age = year - y - (1 if (month, day) < (int(m.group(2)), int(m.group(3))) else 0)
                hit = int(b["min_age"]) <= age < self.adult_age
            else:
                hit = int(b["min_age"]) <= year - y <= int(b["year_only_max_age"])
            if hit:
                out.append({"strength": "strong", "kind": "birth", "rule": "birth_field", "snippet": (key + ": " + "".join(orig[:FIELD_MAX]))[: self.snippet_max]})
        for key in b["age_field_keys"]:
            orig, low, _ = self.normalize(profile.get(key))
            m = self._agefield_rx.search(low)
            if m and int(b["age_min"]) <= int(m.group(1)) <= int(b["age_max"]):
                out.append({"strength": "strong", "kind": "age", "rule": "age_field", "snippet": (key + ": " + "".join(orig[:FIELD_MAX]))[: self.snippet_max]})
        return out

    def scan(self, profiles, handle, today) -> dict:
        """{blocked, kind, signal, signals, soft, soft_years, read}. `profiles` is a list of
        {source, url, name, bio, text, and any birth or age field}; `text` is further profile
        text (an about line, a school, a company), read with the rules for a bio. A strong signal blocks alone; a
        weak one blocks only together with a soft signal in the handle: a birth year (soft) or
        bare years (soft_years)."""
        ymd = _ymd(today)
        soft = self.soft_birth_year(handle, ymd)
        soft_years = self.soft_bare_years(handle)
        signals: list[dict] = []
        seen = set()
        read = set()
        for p in profiles or []:
            if not isinstance(p, dict):
                continue
            source = "".join(list(str(p.get("source") or ""))[:SOURCE_MAX])
            url = "".join(list(str(p.get("url") or ""))[:URL_MAX])
            found = (self._field_signals("name", p.get("name"), ymd) + self._field_signals("bio", p.get("bio"), ymd)
                     + self._field_signals("bio", p.get("text"), ymd) + self._birth_fields(p, ymd))
            keys = ["name", "bio", "text", *self._birth["field_keys"], *self._birth["age_field_keys"]]
            if any(self.normalize(p.get(k))[1] for k in keys):
                read.add(source)
            for s in found:
                key = (s["strength"], s["kind"], source, s["snippet"])
                if key in seen:
                    continue
                seen.add(key)
                signals.append({**s, "source": source, "url": url})
        strong = next((s for s in signals if s["strength"] == "strong"), None)
        weak = next((s for s in signals if s["strength"] == "weak"), None) if soft is not None or soft_years is not None else None
        shown = strong or weak
        # The decision is made over every signal. Only the list handed back is cut, and the
        # signal that decided is always in it.
        listed = signals[: self.signals_max]
        if shown is not None and shown not in listed:
            listed[-1] = shown
        return {"blocked": shown is not None, "kind": strong["kind"] if strong else "soft" if weak else "",
                "signal": shown, "signals": listed, "soft": soft, "soft_years": soft_years, "read": len(read)}


def load(path: str | Path | None = None) -> Engine:
    try:
        with open(path or RULES_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        raise RulesError(type(e).__name__) from e
    return Engine(doc)


try:
    ENGINE: Engine | None = load()
    LOAD_ERROR = ""
except RulesError as _e:      # fail closed: no rules, no adult pass
    ENGINE, LOAD_ERROR = None, str(_e) or "rules"
