#!/usr/bin/env python3
"""ALT-3 v2.8 ledger checker (D50 lane B over v2.7 f009e01e). AUTHOR / SYNTHETIC. Not adopted, no formal H.
v2.8 = v2.7 + D50 C2d X M13: a recorded NON-ACTOR entry is bound in crosscheck by comment id + created_at only,
  and the comment's CURRENT login must NOT be an actor login (an outsider rename or a deleted account = ghost is
  harmless; an actor relabel still fails). Actor entries keep the exact login match. No other change.
v2.7 = v2.6 + D50 C2c X L15 / INFO-5. NON-ACTOR comments (any login outside actor_logins) never hold or reorder:
  L15 crosscheck `pending` lists ACTOR comments only. A non-actor comment can only ever be REJECTED (no state
      effect), so an outsider posting one `LEDGER/1 ` comment per cron cycle can no longer keep H at S1 PENDING.
      A non-actor comment below the ledger head that is not recorded is not COMMENT_NOT_RECORDED either; the
      head used for that check is the highest ACTOR entry.
  INFO-5 a non-actor entry does not advance last_cid (append, and the parse/verify replay in parse_ledger_bytes),
      so an outsider comment recorded with a higher id cannot turn a lagging lower-id ACTOR comment into
      OUT_OF_ORDER. Order is still enforced among actor entries (COMMENT_ORDER / OUT_OF_ORDER_INVALID), and every
      comment id is recorded at most once (DUPLICATE_COMMENT, now checked for every entry). Non-actor entries are
      still recorded (REJECTED ACTOR_NOT_ALLOWED / MALFORMED, never judged by State), still bound by crosscheck
      (login + created_at), and an EDITED entry still requires an actor login (EDITED_INVALID, M10 unchanged).
  Unchanged: every rule for ACTOR comments (EDITED / EDITED_PRESENT, COMMENT_EDITED_AFTER_RECORD, COMMENT_MISSING,
  COMMENT_MISMATCH, STOP_OUT_OF_ORDER, OUT_OF_ORDER_PRESENT -> NOT_COUNTED).
v2.6 (D50 lane B over v2.5 517e876a):
v2.6 = v2.5 + D50 C2b X M10: the EDITED rule applies ONLY to comments whose user.login is an ACTOR LOGIN (any login
in any config `actors` list, plus owner_login, whose STOP / STOP_ALL is always accepted). A comment by any other
login can never be ACCEPTED (actor_ok is false for every kind), so its edits are ignored: unprefixed chatter by a
non-actor is skipped whether edited or not; a prefixed non-actor comment is recorded by the v2.1 rules (REJECTED
ACTOR_NOT_ALLOWED / MALFORMED). An EDITED entry whose actor is not an actor login fails verify (EDITED_INVALID).
verify --comments tolerates a recorded NON-ACTOR entry whose comment was later edited or deleted (it has no state
effect), but still requires an existing comment's login and created_at to match the entry (so an actor's comment
cannot be re-recorded under a non-actor login). Edited or deleted ACTOR comments fail closed exactly as in v2.5.
v2.5 = v2.1 + D50 C2 X H1: every comment must carry `updated_at`. A comment whose updated_at != created_at (edited),
whether or not it carries the `LEDGER/1 ` prefix, is recorded as REJECTED reason EDITED (event null; no state
effect), and start-status is NOT_COUNTED (EDITED_PRESENT) for every window of that ledger (fail closed: a
placeholder edited into START/DONE cannot be backdated, and a STOP edited away cannot silently vanish). verify
--comments fails if a recorded comment was edited after it was recorded; an edited comment not yet recorded is
PENDING. A comment DELETED before the cron reads it remains invisible (N13; GitHub lists no tombstones).
v2.1 = v2 (59cb8a01) + X-13 (63de6dc2): MED-A any OUT_OF_ORDER entry -> start NOT_COUNTED; LOW-B a null REST user is
recorded as login "ghost" (never blocks later appends); LOW-C owner_login type-checked.
v2 = v1 (alt3, e021ae82) + X-12 fixes: HIGH-2 (captured body re-parsed and bound to the entry), HIGH-4 (per-kind
actor lists; the OWNER's STOP / STOP_ALL is always accepted), HIGH-5c (pending comments reported; start-status
never says stopped=false while a ledger comment is pending), HIGH-6 (genesis shape + --pin-genesis-run),
MED full-match IDs, LOW strict int types, empty ledger = clean FAIL.

Modes:
  append  --ledger FILE --comments JSONL --config JSON --run-id ID [--main-sha SHA] [--event-name NAME]
          [--event-comment JSONL]
      ONLY inside the ledger workflow (second principal). Appends one entry per new `LEDGER/1 ` comment in
      comment-id order. Refuses (exit 2) to write onto a ledger that does not verify. A genesis is written only
      when --event-name is workflow_dispatch (the OWNER's step-7 run) or when the event name is not given.
  verify  --repo DIR --ref REF --config JSON [--comments JSONL] [--pin-genesis H] [--pin-genesis-run ID]
          [--pin-commit SHA] [--pin-seq N --pin-hash H]
      H only, on H's own fetch, with H's own API capture in --comments. Exit 0 OK, 1 FAIL.
  start-status  (verify options) --window W [--expect-ref SHA] [--expect-work-key K]
      COUNTED only if: verify OK, --comments given, no pending ledger comment, exactly one ACCEPTED START for W,
      and its ref_sha256 equals --expect-ref (the approval/plan sha that H takes from the hearthbot approval
      anchor, ALT-4). COUNTED still carries stopped/done/stop_all flags: a consumer must read them.

THE LEDGER IS NOT THE EXECUTOR'S STOP CHANNEL. It records STOPs after the fact (cron latency, best effort).
The executor must read STOP from its own STOP channel (Team B design) directly.

Config (v2):
  {"repo": "<owner>/<comments repo>", "issue_number": int, "owner_login": str,
   "actors": {"START":[..],"ACK":[..],"NEXT":[..],"DONE":[..],"STOP":[..],"STOP_ALL":[..]},
   "bot_name": str, "bot_email": str}
  Legacy (v1, kept so X-12's harness runs unchanged): "allowed_actors": [..] instead of "actors" (applies to
  every kind); owner_login defaults to the owner part of "repo". STOP / STOP_ALL from owner_login are always
  accepted. R6: if the OWNER and the executor share one login, ACK/NEXT in the ledger prove nothing about who
  posted them.
"""
import hashlib, json, re, subprocess, sys

ZERO = "0" * 64
ID_RX = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SHA_RX = re.compile(r"[0-9a-f]{64}")
RUN_RX = re.compile(r"[1-9][0-9]{0,19}\.1")
MAIN_RX = re.compile(r"[0-9a-f]{40}")
KINDS = ("START", "ACK", "NEXT", "DONE", "STOP", "STOP_ALL")
PREFIX = "LEDGER/1 "
ENTRY_KEYS = {"v", "seq", "prev", "kind", "comment_id", "comment_created_at", "actor", "body_sha256",
              "event", "verdict", "reason", "run_id", "genesis", "hash"}
GENESIS_KEYS = {"repo", "issue_number", "main_sha"}
LEDGER_FILE = "ledger.jsonl"
GHOST = "ghost"   # login recorded for a comment whose REST user is null (deleted account); never allowed


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def entry_hash(e):
    return sha(canon({k: v for k, v in e.items() if k != "hash"}).encode())


def is_int(x):
    return type(x) is int


def ok_id(s):
    # full match: '$' alone would accept a trailing newline, so newlines are refused explicitly
    return isinstance(s, str) and "\n" not in s and ID_RX.match(s) is not None


def ok_sha(s):
    return isinstance(s, str) and SHA_RX.fullmatch(s) is not None


class Fail(Exception):
    pass


# ---------------------------------------------------------------- rules (deterministic, shared by append and verify)
class State:
    def __init__(self):
        self.stop_all = False
        self.windows = {}
        self.active = None

    def judge(self, ev):
        k, w = ev["kind"], ev["window_id"]
        st = self.windows.get(w)
        if k == "STOP_ALL":
            self.stop_all = True
            self.active = None
            return "ACCEPTED", None
        if k == "STOP":
            st = self.windows.setdefault(w, {"started": False, "stopped": False, "done": False, "acks": 0})
            st["stopped"] = True
            if self.active == w:
                self.active = None
            return "ACCEPTED", None
        if self.stop_all:
            return "REJECTED", "AFTER_STOP_ALL"
        if k == "START":
            if st and st["stopped"]:
                return "REJECTED", "WINDOW_STOPPED"
            if st and st["started"]:
                return "REJECTED", "DUPLICATE_START"
            if self.active is not None:
                return "REJECTED", "OTHER_WINDOW_ACTIVE"
            self.windows[w] = {"started": True, "stopped": False, "done": False, "acks": 0,
                               "work_key": ev["work_key"]}
            self.active = w
            return "ACCEPTED", None
        if not st or not st["started"]:
            return "REJECTED", "NO_START"
        if st["stopped"]:
            return "REJECTED", "AFTER_STOP"
        if st["done"]:
            return "REJECTED", "AFTER_DONE"
        if k == "ACK":
            st["acks"] += 1
            return "ACCEPTED", None
        if k == "NEXT":
            if st["acks"] < 1:
                return "REJECTED", "NEXT_WITHOUT_ACK"
            st["acks"] = 0
            return "ACCEPTED", None
        if k == "DONE":
            st["done"] = True
            if self.active == w:
                self.active = None
            return "ACCEPTED", None
        return "REJECTED", "UNKNOWN_KIND"


def parse_body(body):
    """Return (event, None) or (None, reason). Only the exact canonical single-line form is accepted."""
    if not isinstance(body, str) or not body.startswith(PREFIX):
        return None, "NOT_LEDGER"
    text = body[len(PREFIX):]
    if "\n" in text or "\r" in text:
        return None, "MALFORMED"
    try:
        ev = json.loads(text, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except Exception:
        return None, "MALFORMED"
    if not isinstance(ev, dict) or canon(ev) != text:
        return None, "MALFORMED"
    k = ev.get("kind")
    allowed = {"window_id", "kind", "work_key", "ref_sha256"}
    if set(ev) - allowed or k not in KINDS:
        return None, "MALFORMED"
    if not ok_id(ev.get("window_id")):
        return None, "MALFORMED"
    if k == "START" and not ok_id(ev.get("work_key")):
        return None, "MALFORMED"
    if k in ("START", "ACK") and not ok_sha(ev.get("ref_sha256")):
        return None, "MALFORMED"
    if k not in ("START",) and "work_key" in ev:
        return None, "MALFORMED"
    if k not in ("START", "ACK") and "ref_sha256" in ev:
        return None, "MALFORMED"
    return ev, None


def actor_ok(cfg, actor, kind):
    if kind in ("STOP", "STOP_ALL") and actor == cfg["owner_login"]:
        return True
    return actor in cfg["actors"][kind]


def actor_logins(cfg):
    """v2.6 M10: every login whose comment can ever be an ACCEPTED event (see actor_ok)."""
    return {cfg["owner_login"]}.union(*cfg["actors"].values())


def expected(cfg, st, actor, ev):
    """The verdict append records for a parsed (or unparsable) body; updates st when it judges."""
    if ev is None:
        return "REJECTED", "MALFORMED"
    if not actor_ok(cfg, actor, ev["kind"]):
        return "REJECTED", "ACTOR_NOT_ALLOWED"
    return st.judge(ev)


# ---------------------------------------------------------------- config / ledger parsing
def load_config(path):
    with open(path, encoding="utf-8") as f:
        c = json.load(f)
    base = {"repo", "issue_number", "bot_name", "bot_email"}
    if not isinstance(c, dict) or not base <= set(c) \
            or set(c) - base - {"allowed_actors", "actors", "owner_login"} \
            or (("allowed_actors" in c) == ("actors" in c)):
        raise Fail("CONFIG_INVALID")
    if not is_int(c["issue_number"]) or c["issue_number"] <= 0 or not isinstance(c["repo"], str) \
            or c["repo"].count("/") != 1:
        raise Fail("CONFIG_INVALID")
    c.setdefault("owner_login", c["repo"].split("/")[0])
    if not isinstance(c["owner_login"], str) or not c["owner_login"] or c["owner_login"] == GHOST:
        raise Fail("CONFIG_INVALID")
    if "allowed_actors" in c:
        lst = c.pop("allowed_actors")
        if not isinstance(lst, list) or not lst:
            raise Fail("CONFIG_INVALID")
        c["actors"] = {k: list(lst) for k in KINDS}
    if not isinstance(c["actors"], dict) or set(c["actors"]) != set(KINDS) \
            or not all(isinstance(v, list) and all(isinstance(x, str) and x and x != GHOST for x in v)
                       for v in c["actors"].values()):
        raise Fail("CONFIG_INVALID")
    return c


def parse_ledger_bytes(data, cfg):
    """Parse and fully verify ledger bytes. Returns (entries, state). Raises Fail."""
    if data == b"":
        raise Fail("EMPTY_LEDGER")
    if not data.endswith(b"\n"):
        raise Fail("PARTIAL_LINE")
    entries = []
    for i, line in enumerate(data.split(b"\n")[:-1]):
        try:
            text = line.decode("ascii")
            e = json.loads(text)
        except Exception:
            raise Fail("BAD_JSON seq=%d" % i)
        if not isinstance(e, dict) or set(e) != ENTRY_KEYS or canon(e) != text:
            raise Fail("NON_CANONICAL seq=%d" % i)
        entries.append(e)
    st = State()
    last_cid = -1
    seen_cids = set()
    actors = actor_logins(cfg)
    for i, e in enumerate(entries):
        if not is_int(e["v"]) or not is_int(e["seq"]):
            raise Fail("TYPE seq=%d" % i)
        if e["v"] != 1 or e["seq"] != i:
            raise Fail("SEQ_GAP seq=%d" % i)
        if e["prev"] != (ZERO if i == 0 else entries[i - 1]["hash"]):
            raise Fail("CHAIN_BROKEN seq=%d" % i)
        if e["hash"] != entry_hash(e):
            raise Fail("HASH_MISMATCH seq=%d" % i)
        if not isinstance(e["run_id"], str) or not RUN_RX.fullmatch(e["run_id"]):
            raise Fail("RUN_ID_INVALID seq=%d" % i)
        if i == 0:
            g = e["genesis"]
            if e["kind"] != "GENESIS" or not isinstance(g, dict) or set(g) != GENESIS_KEYS \
                    or g.get("repo") != cfg["repo"] \
                    or not is_int(g.get("issue_number")) or g.get("issue_number") != cfg["issue_number"] \
                    or not (g["main_sha"] is None or (isinstance(g["main_sha"], str)
                                                      and MAIN_RX.fullmatch(g["main_sha"]))):
                raise Fail("GENESIS_INVALID")
            if any(e[k] is not None for k in ("comment_id", "comment_created_at", "actor", "body_sha256",
                                               "event", "verdict", "reason")):
                raise Fail("GENESIS_INVALID")
            continue
        if e["kind"] != "EVENT" or e["genesis"] is not None:
            raise Fail("KIND_INVALID seq=%d" % i)
        cid = e["comment_id"]
        if not is_int(cid) or cid <= 0:
            raise Fail("COMMENT_ID_INVALID seq=%d" % i)
        if not isinstance(e["actor"], str) or not ok_sha(e["body_sha256"]) \
                or not isinstance(e["comment_created_at"], str):
            raise Fail("FIELD_INVALID seq=%d" % i)
        if cid in seen_cids:                        # v2.7: every comment id at most once (all entries)
            raise Fail("DUPLICATE_COMMENT seq=%d" % i)
        seen_cids.add(cid)
        if e["reason"] == "OUT_OF_ORDER":
            if cid >= last_cid or e["verdict"] != "REJECTED" or e["event"] is not None:
                raise Fail("OUT_OF_ORDER_INVALID seq=%d" % i)
            continue
        if e["actor"] in actors:                    # v2.7 INFO-5: only ACTOR entries define the order
            if cid <= last_cid:
                raise Fail("COMMENT_ORDER seq=%d" % i)
            last_cid = cid                          # (a non-actor entry is still replayed below: VERDICT_MISMATCH /
                                                    #  EDITED_INVALID; it can never be ACCEPTED or judged)
        if e["reason"] == "EDITED":
            if e["verdict"] != "REJECTED" or e["event"] is not None or e["actor"] not in actors:
                raise Fail("EDITED_INVALID seq=%d" % i)
            continue
        ev = None
        if e["event"] is not None:
            ev, why = parse_body(PREFIX + canon(e["event"])) if isinstance(e["event"], dict) else (None, "x")
            if ev is None:
                raise Fail("EVENT_INVALID seq=%d" % i)
        want = expected(cfg, st, e["actor"], ev)
        if (e["verdict"], e["reason"]) != want:
            raise Fail("VERDICT_MISMATCH seq=%d recorded=%s/%s rules=%s/%s"
                       % (i, e["verdict"], e["reason"], want[0], want[1]))
    return entries, st


def make_entry(prev_entry, seq, run_id, **kw):
    e = {k: None for k in ENTRY_KEYS}
    e.update({"v": 1, "seq": seq, "prev": prev_entry["hash"] if prev_entry else ZERO, "run_id": run_id})
    e.update(kw)
    e["hash"] = entry_hash(e)
    return e


def read_comments(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            c = json.loads(line)
            out.extend(c if isinstance(c, list) else [c])
    for c in out:
        if isinstance(c, dict) and (c.get("user") is None or (isinstance(c.get("user"), dict)
                                                             and c["user"].get("login") is None)):
            c["user"] = {"login": GHOST, "type": None}       # LOW-B: deleted account, rejected as an actor
        if not isinstance(c, dict) or not is_int(c.get("id")) or not isinstance(c.get("body"), str) \
                or not isinstance(c.get("created_at"), str) or not isinstance(c.get("updated_at"), str) \
                or not isinstance(c.get("user"), dict) \
                or not isinstance(c["user"].get("login"), str):
            raise Fail("COMMENT_SHAPE")
    ids = [c["id"] for c in out]
    if len(ids) != len(set(ids)):
        raise Fail("COMMENT_DUPLICATE_ID")
    return sorted(out, key=lambda c: c["id"])


# ---------------------------------------------------------------- append (workflow only)
def cmd_append(a):
    cfg = load_config(a["--config"])
    if not RUN_RX.fullmatch(a.get("--run-id", "")):
        raise Fail("RUN_ID_INVALID (attempt must be 1)")
    try:
        with open(a["--ledger"], "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = b""
    new = []
    if data:
        entries, st = parse_ledger_bytes(data, cfg)
    else:
        if a.get("--event-name") not in (None, "workflow_dispatch"):
            raise Fail("NO_LEDGER: only the OWNER's workflow_dispatch run may write genesis")
        entries, st = [], State()
        g = make_entry(None, 0, a["--run-id"], kind="GENESIS",
                       genesis={"repo": cfg["repo"], "issue_number": cfg["issue_number"],
                                "main_sha": a.get("--main-sha")})
        entries.append(g)
        new.append(g)
    comments = read_comments(a["--comments"])
    if a.get("--event-comment"):
        byid = {c["id"]: c for c in comments}
        for c in read_comments(a["--event-comment"]):
            byid[c["id"]] = c
        comments = sorted(byid.values(), key=lambda c: c["id"])
    seen = {e["comment_id"] for e in entries[1:]}
    actors = actor_logins(cfg)
    last_cid = max([e["comment_id"] for e in entries[1:] if e["reason"] != "OUT_OF_ORDER" and e["actor"] in actors]
                   or [-1])                                                            # v2.7 INFO-5
    for c in comments:
        edited = c["updated_at"] != c["created_at"] and c["user"]["login"] in actors     # v2.6 M10
        if c["id"] in seen or not (c["body"].startswith(PREFIX) or edited):
            continue
        actor = c["user"]["login"]
        base = dict(kind="EVENT", comment_id=c["id"], comment_created_at=c["created_at"], actor=actor,
                    body_sha256=sha(c["body"].encode("utf-8")))
        if c["id"] < last_cid and actor in actors:                                     # v2.7 INFO-5
            e = make_entry(entries[-1], len(entries), a["--run-id"], verdict="REJECTED", reason="OUT_OF_ORDER",
                           event=None, **base)
        elif edited:
            e = make_entry(entries[-1], len(entries), a["--run-id"], verdict="REJECTED", reason="EDITED",
                           event=None, **base)
            last_cid = c["id"]
        else:
            ev, why = parse_body(c["body"])
            v, r = expected(cfg, st, actor, ev)
            e = make_entry(entries[-1], len(entries), a["--run-id"], verdict=v, reason=r, event=ev, **base)
            if actor in actors:                                                        # v2.7 INFO-5
                last_cid = c["id"]
        entries.append(e)
        new.append(e)
        seen.add(c["id"])
    out = data + b"".join(canon(e).encode() + b"\n" for e in new)
    parse_ledger_bytes(out, cfg)            # self-check before writing
    with open(a["--ledger"], "wb") as f:
        f.write(out)
    print(json.dumps({"appended": len(new), "seq_head": entries[-1]["seq"], "head_hash": entries[-1]["hash"],
                      "verdicts": [[e["comment_id"], e["verdict"], e["reason"]] for e in new if e["seq"] > 0]}))
    return 0


# ---------------------------------------------------------------- verify (H)
def git(repo, *args, binary=False):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    if r.returncode != 0:
        raise Fail("GIT_ERROR " + " ".join(args[:2]) + " " + r.stderr.decode(errors="replace").strip()[:200])
    return r.stdout if binary else r.stdout.decode()


def crosscheck(entries, api, actors):
    """HIGH-2: every entry is bound to a real LEDGER/1 comment whose body re-parses to exactly the recorded
    event. Returns the list of pending (posted, not yet recorded) ledger comments above the head.
    v2.6 M10: a recorded NON-ACTOR entry (never ACCEPTED, no state effect) may later be edited or deleted; an
    existing comment must still carry the recorded login and created_at."""
    for e in entries[1:]:
        c = api.get(e["comment_id"])
        nonactor = e["actor"] not in actors
        if nonactor:                                                                   # v2.8 M13
            if c is None:
                continue
            cur = (c.get("user") or {}).get("login")
            if c["created_at"] != e["comment_created_at"] or cur in actors:
                raise Fail("COMMENT_MISMATCH seq=%d id=%d (non-actor entry not bound)" % (e["seq"], e["comment_id"]))
            if c["updated_at"] != c["created_at"]:
                continue
        if c is None:
            raise Fail("COMMENT_MISSING seq=%d id=%d" % (e["seq"], e["comment_id"]))
        if e["reason"] != "EDITED" and not c["body"].startswith(PREFIX):
            raise Fail("NOT_LEDGER_COMMENT seq=%d id=%d" % (e["seq"], e["comment_id"]))
        login = e["actor"] if nonactor else (c.get("user") or {}).get("login")         # v2.8 M13: rename/ghost ok
        if (login, c["created_at"], sha(c["body"].encode("utf-8"))) != \
                (e["actor"], e["comment_created_at"], e["body_sha256"]):
            raise Fail("COMMENT_MISMATCH seq=%d id=%d (edited or forged)" % (e["seq"], e["comment_id"]))
        if e["reason"] == "EDITED":
            continue
        if c["updated_at"] != c["created_at"]:
            raise Fail("COMMENT_EDITED_AFTER_RECORD seq=%d id=%d" % (e["seq"], e["comment_id"]))
        ev, _ = parse_body(c["body"])
        if e["reason"] == "OUT_OF_ORDER":
            if ev is not None and ev["kind"] in ("STOP", "STOP_ALL"):
                raise Fail("STOP_OUT_OF_ORDER seq=%d id=%d (a STOP was recorded after later events)"
                           % (e["seq"], e["comment_id"]))
            continue
        if canon(ev) != canon(e["event"]):
            raise Fail("EVENT_BODY_MISMATCH seq=%d id=%d (recorded event differs from the comment)"
                       % (e["seq"], e["comment_id"]))
    recorded = {e["comment_id"] for e in entries[1:]}
    top = max([e["comment_id"] for e in entries[1:] if e["actor"] in actors] or [-1])     # v2.7 L15
    pending = []
    for cid, c in sorted(api.items()):
        if (c.get("user") or {}).get("login") not in actors:      # v2.7 L15: a non-actor comment never holds H
            continue
        edited = c["updated_at"] != c["created_at"]                # (actor login, v2.6 M10)
        if cid in recorded or not (c["body"].startswith(PREFIX) or edited):
            continue
        if cid < top:
            raise Fail("COMMENT_NOT_RECORDED id=%d (skipped below the ledger head)" % cid)
        ev, _ = parse_body(c["body"])
        pending.append({"id": cid, "kind": "EDITED" if edited else (ev["kind"] if ev else "MALFORMED")})
    return pending


def verify(a):
    cfg = load_config(a["--config"])
    repo, ref = a["--repo"], a["--ref"]
    head = git(repo, "rev-parse", "--verify", ref + "^{commit}").strip()
    commits = git(repo, "rev-list", "--reverse", "--topo-order", "--parents", head).split("\n")
    commits = [c.split() for c in commits if c.strip()]
    prev_bytes = None
    for row in commits:
        c, parents = row[0], row[1:]
        if prev_bytes is not None and len(parents) == 0:
            raise Fail("SECOND_ROOT " + c[:12])
        if len(parents) > 1:
            raise Fail("MERGE_COMMIT " + c[:12])
        who = git(repo, "show", "-s", "--format=%cn%x00%ce%x00%an%x00%ae", c).strip().split("\x00")
        if who != [cfg["bot_name"], cfg["bot_email"], cfg["bot_name"], cfg["bot_email"]]:
            raise Fail("RAW_COMMIT " + c[:12] + " by " + who[0])
        files = [x for x in git(repo, "ls-tree", "-r", "--name-only", c).split("\n") if x]
        if files != [LEDGER_FILE]:
            raise Fail("TREE_NOT_SINGLE_LEDGER " + c[:12] + " " + ",".join(files)[:120])
        cur = git(repo, "show", c + ":" + LEDGER_FILE, binary=True)
        if prev_bytes is not None:
            if not cur.startswith(prev_bytes) or cur == prev_bytes:
                raise Fail("NOT_APPEND_ONLY " + c[:12])
        parse_ledger_bytes(cur, cfg)        # every intermediate state must verify too
        prev_bytes = cur
    if prev_bytes is None:
        raise Fail("NO_COMMITS")
    entries, st = parse_ledger_bytes(prev_bytes, cfg)
    if a.get("--pin-genesis") and entries[0]["hash"] != a["--pin-genesis"]:
        raise Fail("GENESIS_PIN_MISMATCH (branch recreated?)")
    if a.get("--pin-genesis-run") and entries[0]["run_id"] != a["--pin-genesis-run"]:
        raise Fail("GENESIS_RUN_MISMATCH (genesis not written by the OWNER's step-7 run)")
    if a.get("--pin-commit"):
        r = subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", a["--pin-commit"], head])
        if r.returncode != 0:
            raise Fail("ROLLBACK_OR_FORK pinned commit not an ancestor of " + ref)
    if a.get("--pin-seq") is not None:
        n = int(a["--pin-seq"])
        if n >= len(entries) or entries[n]["hash"] != a.get("--pin-hash"):
            raise Fail("CHECKPOINT_MISMATCH seq=%d" % n)
    pending = None
    if a.get("--comments"):
        api = {c["id"]: c for c in read_comments(a["--comments"])}
        pending = crosscheck(entries, api, actor_logins(cfg))
    return head, entries, st, pending


def cmd_verify(a):
    try:
        head, entries, st, pending = verify(a)
    except Fail as x:
        print(json.dumps({"verdict": "FAIL", "reason": str(x)}))
        return 1
    print(json.dumps({"verdict": "OK", "head": head, "seq_head": entries[-1]["seq"],
                      "head_hash": entries[-1]["hash"], "genesis_hash": entries[0]["hash"],
                      "genesis_run_id": entries[0]["run_id"],
                      "comments_crosschecked": pending is not None,
                      "pending_ledger_comments": pending,
                      "note": "AUTHOR/SYNTHETIC tool. OK is evidence only when run by H with the pinned checker "
                              "sha, on H's own fetch, with H's own API capture and pins from an H checkpoint"}))
    return 0


def start_decision(entries, st, w, pending, expect_ref, expect_wk):
    """Pure decision (unit-tested). Returns the start-status dict."""
    acc = [e for e in entries[1:] if e["verdict"] == "ACCEPTED" and e["event"]["kind"] == "START"
           and e["event"]["window_id"] == w]
    ws = st.windows.get(w, {})
    flags = {"stopped": ws.get("stopped", False), "done": ws.get("done", False), "stop_all": st.stop_all}
    out = {"window": w, "start": "NOT_COUNTED"}
    ooo = [e["comment_id"] for e in entries[1:] if e.get("reason") == "OUT_OF_ORDER"]
    if pending:
        out.update(flags, start="PENDING_LEDGER_COMMENTS", stopped="UNKNOWN", done="UNKNOWN",
                   stop_all="UNKNOWN" if not st.stop_all else True, pending=pending)
        return out
    out.update(flags)
    if pending is None:
        out["reason"] = "COMMENTS_CAPTURE_REQUIRED"
        return out
    if ooo:                         # MED-A: an out-of-order entry may have changed later verdicts
        out.update(reason="OUT_OF_ORDER_PRESENT", out_of_order_ids=ooo)
        return out
    edited = [e["comment_id"] for e in entries[1:] if e.get("reason") == "EDITED"]
    if edited:                      # v2.5 H1: an edited comment may have been a backdated START/DONE or a STOP
        out.update(reason="EDITED_PRESENT", edited_ids=edited)
        return out
    if len(acc) != 1:
        out["reason"] = "ACCEPTED_START_COUNT=%d" % len(acc)
        return out
    ev = acc[0]["event"]
    if not expect_ref:
        out["reason"] = "EXPECT_REF_REQUIRED"
        return out
    if ev["ref_sha256"] != expect_ref or (expect_wk is not None and ev["work_key"] != expect_wk):
        out["reason"] = "START_NOT_BOUND_TO_APPROVAL"
        return out
    out.update(start="COUNTED", seq=acc[0]["seq"], comment_id=acc[0]["comment_id"], work_key=ev["work_key"],
               ref_sha256=ev["ref_sha256"])
    return out


def cmd_start_status(a):
    w = a["--window"]
    try:
        head, entries, st, pending = verify(a)
    except Fail as x:
        print(json.dumps({"window": w, "start": "NOT_COUNTED", "reason": "VERIFY_FAIL " + str(x)}))
        return 1
    out = start_decision(entries, st, w, pending, a.get("--expect-ref"), a.get("--expect-work-key"))
    out["head"] = head
    print(json.dumps(out))
    return 0 if out["start"] == "COUNTED" else 1


def parse_args(argv):
    if not argv:
        raise SystemExit(__doc__)
    mode, a, i = argv[0], {}, 1
    while i < len(argv):
        if not argv[i].startswith("--") or i + 1 >= len(argv):
            raise SystemExit("bad args near " + argv[i])
        a[argv[i]] = argv[i + 1]
        i += 2
    return mode, a


def main(argv):
    mode, a = parse_args(argv)
    try:
        if mode == "append":
            return cmd_append(a)
        if mode == "verify":
            return cmd_verify(a)
        if mode == "start-status":
            return cmd_start_status(a)
    except Fail as x:
        print(json.dumps({"verdict": "REFUSED", "reason": str(x), "start": "NOT_COUNTED"}))
        return 2
    except Exception as x:          # never a traceback: fail closed with JSON
        print(json.dumps({"verdict": "REFUSED", "reason": "INTERNAL " + type(x).__name__, "start": "NOT_COUNTED"}))
        return 2
    raise SystemExit("unknown mode " + mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
