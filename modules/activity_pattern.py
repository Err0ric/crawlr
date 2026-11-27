"""
When an account is active, read from the times of its public actions. Shared by
modules/github_activity.py (public events) and modules/post_activity.py (public posts).

Counting is plain: actions per UTC hour and per weekday (`histogram`).

The one interpretation is `estimate_offset`, a range of UTC offsets that would put the
account's longest quiet stretch at night. It is a hint and is worded as one. It is only made when

  - there are at least ESTIMATE_MIN_EVENTS actions (40)
  - on at least ESTIMATE_MIN_DAYS different UTC days (10)
  - and one quiet stretch of QUIET_MIN_HOURS to QUIET_MAX_HOURS hours (6 to 12) stands out:
    an hour is quiet when it holds at most 2% of the actions, and no second quiet stretch may
    come within an hour of the longest.

Otherwise there is no estimate and a reason says why. The range assumes one person who sleeps
at least six hours inside the quiet stretch with the middle of that sleep between 02:00 and
05:00 local time, so a quiet stretch of L hours starting at hour s UTC gives the offsets
5 - s - L to 2 - s. Shift work, scheduled jobs, bots and shared accounts all break it. An
offset is never a place: no city, no country and no time zone name is derived from it.

Offsets are written in -11..+12, one name per clock time. `utc_offsets` lists them going east.
A range that crosses the date line is two runs, and the label says so.

`compare_offsets` says whether the ranges of two or more answers share an offset. It reads only
`estimate.utc_offsets`, so a page can do the same from the answers it holds.
"""

from datetime import datetime, timezone

ESTIMATE_MIN_EVENTS = 40
ESTIMATE_MIN_DAYS = 10
QUIET_SHARE = 0.02          # an hour with at most this share of the events is quiet
QUIET_MIN_HOURS = 6
QUIET_MAX_HOURS = 12
SLEEP_HOURS = 6             # the block assumed to sit inside the quiet stretch
MIDSLEEP_LOCAL = (2, 5)     # local hours the middle of that block is assumed to fall between

WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")

REASONS = {
    "too_few_events": "Too few {things} to say anything about hours: {events} seen, {need} needed.",
    "too_few_days": "The {short} fall on too few days to show a daily pattern: {days} seen, {need} needed.",
    "no_quiet_window": "No quiet stretch of {need} hours or more: the account is active around the clock.",
    "quiet_window_too_long": "The account is only active in a few hours of the day, so the quiet stretch "
                             "({hours} hours) is too long to place a night in.",
    "ambiguous_quiet_window": "Two quiet stretches of about the same length, so neither can be called the night.",
}


def _when(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # A date at the edge of the calendar with an offset cannot be moved to UTC.
        return d.astimezone(timezone.utc) if d.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hh(hour: int) -> str:
    return f"{hour % 24:02d}:00"


def _utc(offset: int) -> str:
    return "UTC" if offset == 0 else f"UTC{offset:+d}"


def _name(offset: int) -> int:
    """An offset as its one name in -11..+12."""
    return (offset + 11) % 24 - 11


def offsets_label(offsets: list[int]) -> str:
    """Offsets listed going east, as words. A list that crosses the date line (+12 then -11) is
    two runs joined by "or", so it cannot be read as one span from the first to the last."""
    runs: list[list[int]] = []
    for o in offsets:
        if runs and o == runs[-1][-1] + 1:
            runs[-1].append(o)
        else:
            runs.append([o])
    return " or ".join(_utc(r[0]) if len(r) == 1 else f"{_utc(r[0])} to {_utc(r[-1])}" for r in runs)


def quiet_runs(hours: list[int]) -> list[tuple[int, int]]:
    """Circular runs of quiet hours as (start hour, length), longest first."""
    total = sum(hours)
    limit = int(total * QUIET_SHARE)
    quiet = [h <= limit for h in hours]
    if all(quiet) or not any(quiet):
        return []
    # Start walking just after an active hour so no run is split across midnight.
    origin = next(i for i in range(24) if not quiet[i]) + 1
    runs: list[tuple[int, int]] = []
    start, length = None, 0
    for step in range(24):
        hour = (origin + step) % 24
        if quiet[hour]:
            start = hour if start is None else start
            length += 1
        elif start is not None:
            runs.append((start, length))
            start, length = None, 0
    if start is not None:
        runs.append((start, length))
    return sorted(runs, key=lambda r: (-r[1], r[0]))


def estimate_offset(hours: list[int], events: int, active_days: int, window_days: int,
                    things: str = "public events") -> tuple[dict | None, dict | None]:
    """(estimate, reason). Exactly one of the two is None. `things` names what was counted."""

    def no(code: str, **kw) -> tuple[None, dict]:
        return None, {"code": code, "text": REASONS[code].format(things=things, short=things.split()[-1], **kw)}

    if events < ESTIMATE_MIN_EVENTS:
        return no("too_few_events", events=events, need=ESTIMATE_MIN_EVENTS)
    if active_days < ESTIMATE_MIN_DAYS:
        return no("too_few_days", days=active_days, need=ESTIMATE_MIN_DAYS)
    runs = quiet_runs(hours)
    if not runs or runs[0][1] < QUIET_MIN_HOURS:
        return no("no_quiet_window", need=QUIET_MIN_HOURS)
    start, length = runs[0]
    if length > QUIET_MAX_HOURS:
        return no("quiet_window_too_long", hours=length)
    if len(runs) > 1 and runs[1][1] >= length - 1:
        return no("ambiguous_quiet_window")

    # The middle of the assumed sleep can sit anywhere the block still fits in the quiet stretch.
    low = MIDSLEEP_LOCAL[0] - (start + length - SLEEP_HOURS // 2)
    high = MIDSLEEP_LOCAL[1] - (start + SLEEP_HOURS // 2)
    offsets = [_name(low + i) for i in range(high - low + 1)]     # going east, each in -11..+12
    end = (start + length) % 24
    return {
        "utc_offset_from": offsets[0],
        "utc_offset_to": offsets[-1],
        "utc_offsets": offsets,
        "crosses_date_line": offsets[0] > offsets[-1],
        "label": offsets_label(offsets),
        "quiet_start_hour": start,
        "quiet_end_hour": end,                         # the first active hour after the stretch
        "quiet_hours": length,
        "quiet_events": sum(hours[(start + i) % 24] for i in range(length)),
        "basis": (f"Based on {events} {things} over {window_days} day{'s' if window_days != 1 else ''} "
                  f"({active_days} with activity). The longest quiet stretch is {_hh(start)} to {_hh(end)} UTC."),
        "assumption": ("Assumes one person who sleeps at least 6 hours inside the quiet stretch, with the middle "
                       "of that sleep between 02:00 and 05:00 local time."),
        "caveat": ("A hint, not a fact. Shift work, scheduled jobs, bots and shared accounts all break it, "
                   "and a UTC offset is not a place."),
    }, None


def histogram(times) -> dict:
    """Counts over datetimes in UTC: {events, window, hours_utc, weekdays_utc, weekday_labels}.
    The same keys modules/github_activity.py answers with."""
    hours, weekdays = [0] * 24, [0] * 7
    days: set = set()
    first = last = None
    count = 0
    for d in times:
        count += 1
        hours[d.hour] += 1
        weekdays[d.weekday()] += 1
        days.add(d.date())
        first = d if first is None or d < first else first
        last = d if last is None or d > last else last
    return {
        "events": count,
        "window": {"first": _iso(first) if first else "", "last": _iso(last) if last else "",
                   "days": (last.date() - first.date()).days + 1 if count else 0, "active_days": len(days)},
        "hours_utc": hours,                    # index 0 is 00:00 to 00:59 UTC
        "weekdays_utc": weekdays,              # index 0 is Monday
        "weekday_labels": list(WEEKDAYS),
    }


def compare_offsets(answers: list) -> dict:
    """Do the offset ranges of several activity answers fit together?

    Each answer is what github-activity or post-activity returned. Only `estimate.utc_offsets`
    is read; an answer without an estimate (any state, any reason) takes no part.

      agree            two or more ranges, and at least one offset is in all of them
      disagree         two or more ranges, and no offset is in all of them
      not_enough_data  fewer than two answers carry a range

    `shared` is the offsets in every range, going east, and `label` words them. Agreeing ranges
    do not show one person: a third of the world shares any three offsets. Disagreeing ranges
    do not show two people either: one account may be scheduled, or used at work only."""
    ranges = []
    for a in answers if isinstance(answers, list) else []:
        est = a.get("estimate") if isinstance(a, dict) else None
        offs = est.get("utc_offsets") if isinstance(est, dict) else None
        if isinstance(offs, list) and offs and all(isinstance(o, int) and not isinstance(o, bool) and -11 <= o <= 12 for o in offs):
            ranges.append(offs)
    if len(ranges) < 2:
        return {"verdict": "not_enough_data", "compared": len(ranges), "shared": [], "label": ""}
    shared = [o for o in ranges[0] if all(o in r for r in ranges[1:])]      # keeps the first range's eastward order
    return {"verdict": "agree" if shared else "disagree", "compared": len(ranges), "shared": shared,
            "label": offsets_label(shared) if shared else ""}
