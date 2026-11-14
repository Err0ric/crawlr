"""
Tell a person's bio apart from the text a platform writes about every account.

Profile pages put a description in their meta tags whether or not the owner wrote one. When
there is no bio the platform fills it with a template ("x streams live on Twitch! ..."), and
scrapers that read og:description hand that back as if the person had written it.

`clean_bio` returns the part of the text a person wrote, which is often nothing.
`is_boilerplate_bio` is true when nothing is left.

How the templates work:

- The known handle and display name are swapped for a NAME token first, so a template is
  written once and fits any account. `{n}` in a template matches that token, or a short run
  of text when the caller did not know the name; `{h}` is the same for a handle.
- FULL templates must match the whole text. A real bio that merely mentions a platform
  ("I stream on Twitch every Friday") does not match.
- PREFIX and SUFFIX templates are cut off and the rest is kept, for descriptions that wrap
  the real bio in stats ("12 Followers, 3 Following, 9 Likes - <bio>").

To add a platform: record what its page says for an account with no bio, replace the handle
and name with `{n}`, and add the line under the platform's key. Add the string to
tests/test_boilerplate.py.
"""

import html
import re

_NAME = "\x00"
# A name: the NAME token (one character), or a short run of text when the caller did not
# know the name, or knew only part of it.
# Sentence punctuation is left out so an unknown name cannot swallow the bio that follows it.
_N = r"[^\n.!?|]{1,80}?"
# `{h}` is a handle: the token, or a run of handle characters.
_H = r"(?:\x00|[\w.\-]{1,40})"
# "Name (@handle)", or just one of them.
_WHO = rf"(?:{_N}\s*\(@?{_H}\)|@{_H}|{_N})"
_NUM = r"[\d][\d.,]*\s?[KkMmBb]?"

_APOS = "['’]"


def _t(pattern: str) -> str:
    """Expand the shorthand used in the tables below into a regex."""
    return (pattern.replace("{who}", _WHO).replace("{n}", _N).replace("{h}", _H).replace("{num}", _NUM)
            .replace("{'}", _APOS).replace(" ", r"\s+"))


# Whole-text templates, by platform. Every list is tried for every text (each template names
# its own platform, so they cannot collide); the grouping is for the person maintaining it.
FULL = {
    "twitch": [
        r"{n} streams live on Twitch! Check out their videos, sign up to chat, and join their community\.?",
        r"Twitch is the world{'}s leading video platform and community for gamers\.?",
    ],
    "patreon": [
        r"Join {n} on Patreon for exclusive content and member-only benefits from your favorite creators\. Get access today!?",
        r"Become a patron of {n} today:? .{0,200}",
        r"Patreon is empowering a new generation of creators\..{0,300}",
    ],
    "facebook": [
        r"{n} is on Facebook\. Join Facebook to connect with {n} and others you may know\..{0,200}",
        r"Log in(?:to)? (?:to )?Facebook to start sharing and connecting with your friends, family,? and people you know\.?",
    ],
    "snapchat": [
        r"{n} is on Snapchat!\s*(?:\(@?{h}\))?",
    ],
    "youtube": [
        r"Share your videos with friends, family,? and the world\.?",
        r"Enjoy the videos and music you love, upload original content,? and share it all with friends, family,? and the world on YouTube\.?",
    ],
    "instagram": [
        r"{num} Followers, {num} Following, {num} Posts - See Instagram photos and videos from {who}",
        r"Create an account or log in to Instagram\b.{0,300}",
    ],
    "x": [
        r"The latest (?:posts|tweets) from {who}\.?",
        r"{num} followers? · {num} following\.(?: Joined [A-Za-z]{3,9} \d{4}\.)? See the latest conversations with @?{h}\.?",
    ],
    "threads": [
        r"{num} Followers? • {num} Threads\. See the latest conversations with @?{h}\.?",
        r"Join Threads to share ideas, ask questions, post random thoughts, find your people and more\..{0,80}",
    ],
    "pinterest": [
        r"See what {who} has discovered on Pinterest, the world{'}s biggest collection of ideas\.?",
        r"Discover recipes, home ideas, style inspiration and other ideas to try\.?",
    ],
    "soundcloud": [
        r"Listen to {n} \| SoundCloud is an audio platform that lets you listen to what you love and share the sounds you create\.?",
        r"Play {n} and discover followers on SoundCloud \| Stream tracks, albums, playlists on desktop and mobile\.?",
    ],
    "linktree": [
        r"Linktree\. Make your link do more\.?",
        r"(?:View|Find) {n}{'}s Linktree\b.{0,200}",
    ],
    "medium": [
        r"Read writing from {n} on Medium\.?",
        r"Medium is an open platform where readers find dynamic thinking,? and where expert and undiscovered voices can share their writing on any topic\.?",
    ],
    "reddit": [
        r"Reddit is a network of communities where people can dive into their interests, hobbies and passions\..{0,120}",
    ],
    "github": [
        r"{n} has {num} repositor(?:y|ies) available\. Follow their code on GitHub\.?",
        r"GitHub is where {n} builds software\.?",
    ],
    "cashapp": [
        r"Pay \$?{n} on Cash App\.?",
        r"Instantly exchange money for free on Cash App\.?",
        r"Cash App is the easiest way to send, spend, save,? and invest your money\..{0,200}",
    ],
    "onlyfans": [
        r"OnlyFans is the social platform revolutionizing creator and fan connections\..{0,400}",
    ],
    "telegram": [
        r"You can contact @?{h} right away\.?",
        r"You can view and join @?{h} right away\.?",
    ],
    "tiktok": [
        r"No bio yet\.?",
        r"Watch awesome short videos created by {n}",
        r"{who} on TikTok \| Watch the latest video from {who}\.?",
    ],
}

# Cut from the front; whatever follows is kept.
PREFIX = {
    "tiktok": [
        r"(?:@?{h} )?{num} Followers, {num} Following, {num} Likes -",
        r"{who} on TikTok \| {num} Likes\. {num} Followers\.",
    ],
    "instagram": [
        r"{num} Followers, {num} Following, {num} Posts - {who} on Instagram:",
    ],
    "x": [
        r"The latest (?:posts|tweets) from {who}\.",
    ],
    "threads": [
        r"{num} Followers? • {num} Threads •",
    ],
    "medium": [
        r"Read writing from {n} on Medium\.",
    ],
}

# Cut from the end; whatever comes before is kept.
SUFFIX = {
    "tiktok": [
        r"-?\s*Watch awesome short videos created by {n}",
        r"\.?\s*Watch the latest video from {who}\.?",
    ],
    "threads": [
        r"\.? See the latest conversations with @?{h}\.?",
    ],
    "medium": [
        r"Every day, {n} and thousands of other voices read, write, and share important stories on Medium\.?",
    ],
}

ALIASES = {
    "twitter": "x", "cash app": "cashapp", "cash.app": "cashapp", "linktr.ee": "linktree",
    "threads.net": "threads", "facebook.com": "facebook",
}

_FLAGS = re.IGNORECASE | re.DOTALL


def _compile(table: dict, fmt: str) -> dict:
    return {key: [re.compile(fmt.format(_t(p)), _FLAGS) for p in pats] for key, pats in table.items()}


_FULL = _compile(FULL, "^(?:{})$")
_PREFIX = _compile(PREFIX, "^(?:{})\\s*")
_SUFFIX = _compile(SUFFIX, "\\s*(?:{})$")


def _platform_key(platform: str) -> str:
    p = (platform or "").strip().lower()
    return ALIASES.get(p, p.replace(" ", ""))


def _ordered(table: dict, key: str) -> list:
    """The named platform's templates first, then everyone else's."""
    first = table.get(key, [])
    return first + [rx for k, pats in table.items() if k != key for rx in pats]


def _tokenize(text: str, names: list[str]) -> tuple[str, list[str]]:
    """Swap each known name (whole words only) for the NAME token. Also returns the names as
    they were written, in order, so any that sit in the person's own text can be put back."""
    known = sorted({n for n in names if len(n) >= 2}, key=len, reverse=True)
    if not known:
        return text, []
    rx = re.compile("|".join(rf"(?<![\w@])@?{re.escape(n)}(?!\w)" for n in known), re.IGNORECASE)
    written: list[str] = []

    def swap(m: re.Match) -> str:
        written.append(m.group(0))
        return _NAME

    return rx.sub(swap, text), written


def _is_full(tokens: str, key: str) -> bool:
    return any(rx.match(tokens) for rx in _ordered(_FULL, key))


def clean_bio(text, platform: str = "", username: str = "", display_name: str = "") -> str:
    """Return the part of `text` a person wrote, or "" when it is all platform boilerplate."""
    if not isinstance(text, str):
        return ""
    original = re.sub(r"\s+", " ", html.unescape(text)).strip()
    if not original:
        return ""
    key = _platform_key(platform)
    names = [str(username or "").strip().lstrip("@"), str(display_name or "").strip()]
    tokens, written = _tokenize(original, names)
    out = _strip(tokens, written, key)
    if out == tokens and written:
        # A handle that is also a word in the template ("instagram" on Instagram) hides the
        # template once it is swapped out. Try the text as written.
        out = _strip(original, [], key)
    return original if out in (tokens, original) else out


def _strip(tokens: str, written: list[str], key: str) -> str:
    """Remove boilerplate from tokenized text. Returns it unchanged when there is none."""
    # A bio that is only the platform's own name, or only the handle, says nothing.
    if _is_empty(tokens, key) or _is_full(tokens, key):
        return ""

    cut = tokens
    for rx in _ordered(_PREFIX, key):
        cut, n = rx.subn("", cut, count=1)
        if n:
            break
    skipped = tokens.count(_NAME) - cut.count(_NAME)     # names that went with the prefix
    after_prefix = cut
    for rx in _ordered(_SUFFIX, key):
        cut, n = rx.subn("", cut, count=1)
        if n:
            break
    if cut == tokens:
        return tokens
    cut = cut.strip()
    if len(cut) >= 2 and cut[0] in "\"\u201c" and cut[-1] in "\"\u201d":
        cut = cut[1:-1].strip()          # `... on Instagram: "bio"`
    # Stats with nothing after them are all boilerplate; so is a remainder that is itself a
    # template ("... Likes - Watch awesome short videos created by x").
    if _is_empty(cut, key) or _is_full(cut, key) or _is_full(after_prefix.strip(), key):
        return ""
    # Names left in the person's own text go back in as they were written.
    parts = cut.split(_NAME)
    out = [parts[0]]
    for i, part in enumerate(parts[1:]):
        out.append(written[skipped + i] if skipped + i < len(written) else "")
        out.append(part)
    return "".join(out).strip()


def _is_empty(tokens: str, key: str) -> bool:
    bare = tokens.replace(_NAME, "").strip(" @()|-\u00b7\u2022.\"").lower()
    return not bare or bool(key and bare.replace(" ", "") == key)


def is_boilerplate_bio(text, platform: str = "", username: str = "", display_name: str = "") -> bool:
    """True when `text` has content and all of it is platform boilerplate."""
    if not isinstance(text, str) or not text.strip():
        return False
    return clean_bio(text, platform, username, display_name) == ""
