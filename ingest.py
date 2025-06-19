"""cve_ingest_service.py
================================================
A drop‑in service module that
    • Resolves CVEs for a batch of CPE names.
    • Evaluates each CVE’s configuration expressions (Boolean logic over
      CPE‑Match‑Criteria IDs) against the *full* set of match strings that
      belong to the supplied CPE list.
    • Inserts new rows into ``current_sw_state`` in bulk (deduplicating by
      ``sw_branch`` + ``run``) and writes matching history rows in the same
      transaction.

Assumptions
-----------
* PostgreSQL 10+ (uses ``DISTINCT ON``).
* ``runs`` model has an ``e_release`` FK that can be used for
  ``first_detected_at`` on the *first* appearance of the CVE.
* All models imported from ``myapp.models`` already exist exactly as sent in
  earlier snippets.

Usage
-----
```python
from myapp.services.cve_ingest_service import ingest_cves_for_cpes

added = ingest_cves_for_cpes(
    sw_branch=branch_obj,
    run=run_obj,
    cpe_names=[...],
    acting_user=request.user,   # or a System user
)
print(f"Imported {added} new CVE states")
```"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Callable, Collection, List, Set

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Prefetch
from django.utils import timezone

from myapp.models import (
    CPEEntry,
    CPEMatchString,
    CVE,
    current_sw_state,
    cve_history2,
    runs,
    sw_branches,
)

# ---------------------------------------------------------------------------
#  Expression‑compiler (cached)
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|AND|OR|[A-Za-z0-9_.:-]+", re.IGNORECASE)

@lru_cache(maxsize=None)
def compile_expression(expr: str) -> Callable[[Set[str]], bool]:
    """Return a *callable* that evaluates *expr* against a set of tokens.

    Supported operators: **AND**, **OR**, and parentheses.  Every other token
    is treated as a literal Match‑Criteria ID.
    """
    tokens: list[str] = []
    for part in _TOKEN_RE.findall(expr):
        upper = part.upper()
        if upper == "AND":
            tokens.append("and")
        elif upper == "OR":
            tokens.append("or")
        elif part in ("(", ")"):
            tokens.append(part)
        else:
            # safe quoting; membership test resolved at run‑time
            tokens.append(f"({part!r} in token_set)")
    python_expr = " ".join(tokens) if tokens else "True"
    return eval(f"lambda token_set: {python_expr}", {}, {})


# ---------------------------------------------------------------------------
#  Main service function
# ---------------------------------------------------------------------------

User = get_user_model()

def ingest_cves_for_cpes(*,
    sw_branch: sw_branches,
    run: runs,
    cpe_names: Collection[str],
    acting_user: User,
    chunk_size: int = 5_000,
) -> int:
    """Import CVEs for a list of CPE names into *current_sw_state*.

    Parameters
    ----------
    sw_branch : sw_branches
        Branch the rows belong to.
    run : runs
        The *latest* run object.
    cpe_names : Collection[str]
        Collection of CPE names (strings) to resolve.
    acting_user : User
        The user responsible for the ingest (audit trail).
    chunk_size : int, default 5000
        Batch size for bulk inserts.

    Returns
    -------
    int
        Number of *new* ``current_sw_state`` rows created.
    """
    # ------------------------------------------------------------------
    # 1  Build the *truth set* of Match‑Criteria IDs for these CPEs
    # ------------------------------------------------------------------
    truth_tokens: Set[str] = set(
        CPEMatchString.objects
        .filter(cpe_entry__cpe_name__in=cpe_names)
        .values_list("match_criteria_id", flat=True)
    )

    matchstring_subq = CPEMatchString.objects.filter(
        cpe_entry__cpe_name__in=cpe_names
    )

    # ------------------------------------------------------------------
    # 2  Fetch candidate CVEs (+prefetch expressions / metrics etc.)
    # ------------------------------------------------------------------
    cve_qs = (
        CVE.objects
        .filter(cpe_match_id__in=matchstring_subq)
        .distinct()
        .prefetch_related(
            Prefetch("ConfigureExpressions", to_attr="pref_expressions"),
            Prefetch("metrics",            to_attr="pref_metrics"),
            Prefetch("weaknesses",         to_attr="pref_weaknesses"),
            Prefetch("descriptions",       to_attr="pref_descriptions"),
        )
        .only("id", "vuln_status", "published", "last_modified")
    )
    all_cves: List[CVE] = list(cve_qs)

    # ------------------------------------------------------------------
    # 3  Evaluate configuration expressions in Python (no extra SQL)
    # ------------------------------------------------------------------
    valid_cves: List[CVE] = []
    for cve in all_cves:
        expressions = [ce.expression for ce in getattr(cve, "pref_expressions", [])]
        if not expressions:
            # No configuration → universally applicable
            valid_cves.append(cve)
            continue
        if any(compile_expression(expr)(truth_tokens) for expr in expressions):
            valid_cves.append(cve)

    if not valid_cves:
        return 0

    # ------------------------------------------------------------------
    # 4  Grab the latest existing state rows for these CVEs & branch
    # ------------------------------------------------------------------
    latest_states = {
        row.cve_id: row
        for row in (
            current_sw_state.objects
            .filter(sw_branch_id=sw_branch, cve_id__in=[c.id for c in valid_cves])
            .order_by("cve_id", "-last_modified_run_id")
            .distinct("cve_id")              # DISTINCT ON (PostgreSQL)
        )
    }

    # ------------------------------------------------------------------
    # 5  Prepare the new state + history records in memory
    # ------------------------------------------------------------------
    now = timezone.now()
    new_state_rows = []
    new_history_rows = []

    for cve in valid_cves:
        prev = latest_states.get(cve.id)
        if prev and prev.last_modified_run_id_id == run.id:
            # Already recorded for *this* run → nothing to do
            continue

        # Copy most fields from the previous row (if any)
        state_kwargs = {}
        if prev:
            for f in current_sw_state._meta.concrete_fields:
                if f.primary_key or f.auto_created:
                    continue
                if f.name in (
                    "id", "created_at", "updated_at",
                    "first_detected_at", "last_modified_by_user_id",
                    "last_modified_run_id", "sw_branch_id",
                ):
                    continue
                state_kwargs[f.name] = getattr(prev, f.name)

        metrics = getattr(cve, "pref_metrics", [])
        base_score = metrics[0].base_score if metrics else None

        new_state = current_sw_state(
            **state_kwargs,
            cve_id=cve.id,
            first_detected_at=prev.first_detected_at if prev else run.e_release,  # adapt if model differs
            last_modified_by_user_id=acting_user,
            last_modified_run_id=run,
            sw_branch_id=sw_branch,
            cvss_score=base_score,
            created_at=now,
            updated_at=now,
        )
        new_state_rows.append(new_state)

    # ------------------------------------------------------------------
    # 6  Bulk‑create states & histories inside a single transaction
    # ------------------------------------------------------------------
    with transaction.atomic():
        created_states = current_sw_state.objects.bulk_create(
            new_state_rows,
            batch_size=chunk_size,
            ignore_conflicts=True,
        )

        for st in created_states:
            new_history_rows.append(
                cve_history2(
                    cve_id=st,
                    run_id=run,
                    Changes={
                        "change": [{
                            "method": "Added",
                            "date": now.strftime("%m/%d/%Y, %H:%M:%S"),
                            "user": acting_user.username,
                        }]
                    },
                    read_status=True,
                )
            )

        cve_history2.objects.bulk_create(
            new_history_rows,
            batch_size=chunk_size,
            ignore_conflicts=True,
        )

    return len(created_states)



# services/cve_ingest.py
from collections import defaultdict
from datetime import datetime

from django.db import transaction
from django.db.models import (
    Exists, OuterRef, Subquery, F, Q, Value, BooleanField, Prefetch,
)
from django.utils import timezone

from myapp.models import (
    CPEEntry, CVE, CPEMatchString, current_sw_state,
    cve_history2, runs, sw_branches
)


def ingest_cves_for_cpes(
    *,                                   # force kw-args
    sw_branch: sw_branches,
    run: runs,
    cpe_names: list[str],
    acting_user,                         # request.user (or a system user)
    chunk_size: int = 1_000,            # tune if you hit memory limits
) -> int:
    """
    1. Find every CVE referenced by ANY of `cpe_names`.
    2. Write them into `current_sw_state` for `sw_branch` & `run`
       (duplicating the latest row when the CVE already exists for an older run).
    3. Record a history entry per row.
    Returns the count of *new* current_sw_state rows written.
    """
    # ------------------------------------------------------------
    #   Phase 1 – Resolve CPE → CVE in a single DB round-trip
    # ------------------------------------------------------------
    cpe_ids = (
        CPEEntry.objects
        .filter(cpe_name__in=cpe_names)
        .values_list("id", flat=True)
    )

    cve_qs = (
        CVE.objects
        .filter(cpe_match_id__cpe_entry__in=cpe_ids)
        .distinct()
        .only("id", "vuln_status")      # grab only columns we really need
        .prefetch_related(
            Prefetch("metrics"),        # CVSS scores
            Prefetch("weaknesses"),
            Prefetch("descriptions"),
        )
    )
    all_cves = list(cve_qs)             # materialise once – still one query

    # ------------------------------------------------------------
    #   Phase 2 – Look up *existing* rows for this branch
    # ------------------------------------------------------------
    existing_latest = {
        row.cve_id: row
        for row in (
            current_sw_state.objects
            .filter(sw_branch_id=sw_branch, cve_id__in=[c.id for c in all_cves])
            .order_by("cve_id", "-last_modified_run_id")   # newest first
            .distinct("cve_id")                            # PostgreSQL–only
        )
    }

    # ------------------------------------------------------------
    #   Phase 3 – Build new current_sw_state objects in memory
    # ------------------------------------------------------------
    now = timezone.now()

    new_states = []
    new_histories = []

    for cve in all_cves:
        prev = existing_latest.get(cve.id)

        if prev and prev.last_modified_run_id_id == run.id:
            # We have *already* recorded this CVE for this run; skip
            continue

        # Either no previous row, or previous row is from an older run → duplicate
        # Copy every field *except* pk, date fields, run/branch/user-tracking
        base_kwargs = {}
        if prev:
            # Copy fields quickly with model_to_dict if you wish; here is manual:
            for f in current_sw_state._meta.concrete_fields:   # type: ignore
                if f.name in (
                    "id", "created_at", "updated_at",
                    "first_detected_at",
                    "last_modified_by_user_id",
                    "last_modified_run_id",
                    "sw_branch_id",
                ):
                    continue
                base_kwargs[f.name] = getattr(prev, f.name)

        state_obj = current_sw_state(
            **base_kwargs,
            cve_id=cve.id,
            first_detected_at=prev.first_detected_at if prev else run.e_release,  # or custom logic
            last_modified_by_user_id=acting_user,
            last_modified_run_id=run,
            sw_branch_id=sw_branch,
            tool_state=current_sw_state.New if prev is None else prev.tool_state,
            created_at=now,
            updated_at=now,
            cvss_score=cve.metrics.first().base_score if cve.metrics.exists() else None,
        )
        new_states.append(state_obj)

    # ------------------------------------------------------------
    #   Phase 4 – bulk_create + history (inside one transaction)
    # ------------------------------------------------------------
    with transaction.atomic():
        created_states = current_sw_state.objects.bulk_create(
            new_states, batch_size=chunk_size, ignore_conflicts=True
        )

        # Build `cve_history2` in matching order
        for st in created_states:
            chn = {
                "change": [
                    {
                        "method": "Added",
                        "date": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                        "user": acting_user.username,
                    }
                ]
            }
            new_histories.append(
                cve_history2(
                    cve_id=st,
                    run_id=run,
                    Changes=chn,
                    read_status=True,
                )
            )

        cve_history2.objects.bulk_create(new_histories, batch_size=chunk_size)

    return len(created_states)






-- speed the CVE→CPE join
CREATE INDEX idx_cpe_matchstring_cpe_entry
    ON myapp_cpematchstring_cpe_entry (cpematchstring_id, cpeentry_id);

CREATE INDEX idx_cvemtomatchstring
    ON myapp_cve_cpe_match_id (cve_id, cpematchstring_id);

-- uniqueness / dedup safety
CREATE UNIQUE INDEX uniq_state
    ON myapp_current_sw_state (cve_id, sw_branch_id, last_modified_run_id_id);






time python manage.py shell <<'PY'
from myapp.services.cve_ingest import ingest_cves_for_cpes
from myapp.models import sw_branches, runs
sw = sw_branches.objects.get(name="EURO_BRANCH")
run = runs.objects.latest('id')
names = list(open('10k_cpenames.txt'))         # 10 000 random CPEs
print("inserted", ingest_cves_for_cpes(
        sw_branch=sw, run=run,
        cpe_names=names, acting_user_id=1))
PY





# Step 1 – From the incoming CPE list, collect **every** match_criteria_id
truth_tokens = set(
    CPEMatchString.objects
        .filter(cpe_entry__cpe_name__in=cpe_names)
        .values_list("match_criteria_id", flat=True)
)





valid_cves = []
for cve in all_cves:                                # pre-fetched QS
    exprs = [ce.expression for ce in cve.ConfigureExpressions.all()]

    if not exprs:                                   # no configs ⇒ keep
        valid_cves.append(cve)
        continue

    # Keep the CVE as soon as *one* expression evaluates True
    if any(compile_expression(expr)(truth_tokens) for expr in exprs):
        valid_cves.append(cve)
