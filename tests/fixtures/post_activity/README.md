Shapes of the three sources modules/post_activity.py reads, recorded on 2026-11-27 from
project accounts and then rewritten: every account, id, time and title here is invented.
The tests build their rows from these shapes.

- hn_search.json: the Hacker News search index answer (`hits` with `created_at_i` and `_tags`)
- mastodon.json: the account lookup and one status row, with the fields this module reads
- lobsters.json: the user record and one story row
