"""Reproducible evaluation on a SMALL hand-written synthetic set (authored by the developer: optimistic, not a real-world benchmark)."""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from datetime import datetime, timezone
from app.intelligence import extract_facts, assess_risk
REF = datetime(2026, 10, 18, tzinfo=timezone.utc)
# (text, expected [(kind, iso-prefix)])
EXTRACT = [
 ("Applications close 24 Oct 5:00 PM.", [("deadline", "2026-10-24T17:00")]),
 ("Your interview is on 22 October 3:00 PM.", [("interview", "2026-10-22T15:00")]),
 ("The Data Structures exam is on Oct 22 at 10 AM.", [("exam", "2026-10-22T10:00")]),
 ("Last date to submit documents: 5 Nov 2026.", [("deadline", "2026-11-05T00:00")]),
 ("Interview scheduled for 3rd Nov, 11:30 AM.", [("interview", "2026-11-03T11:30")]),
 ("Submission due 12 Dec 11:59 PM.", [("deadline", "2026-12-12T23:59")]),
 ("Lunch is on Friday.", []), ("Thanks for applying, we will be in touch.", []),
 ("Please find the brochure attached.", []), ("The deadline is next week.", []),
 ("Pay to A/C 123456789012 IFSC HDFC0001234.", [("payment_instruction", "A/C 123456789012 | IFSC HDFC0001234")]),
 ("Exam on 7 Jan 2027 9:00 AM. Interview on 8 Jan 2027 2:00 PM.", [("exam", "2027-01-07T09:00"), ("interview", "2027-01-08T14:00")]),
]
tp = fp = fn = 0
for text, exp in EXTRACT:
    got = {(k, v[:len(e)]) for k, v, _ in extract_facts(text, REF) for (ek, e) in exp if k == ek} | {(k, v) for k, v, _ in extract_facts(text, REF) if k not in {x[0] for x in exp}}
    want = {(k, v) for k, v in exp}
    tp += len(got & want); fp += len(got - want); fn += len(want - got)
print(f"extraction  items={sum(len(e) for _, e in EXTRACT)} precision={tp/max(tp+fp,1):.2f} recall={tp/max(tp+fn,1):.2f} (tp={tp} fp={fp} fn={fn})")
RISK = [  # (sender, subject, body, known, is_risky)
 ("hr@northwind-careers.co","Slot","Pay registration fee today only",["northwind.com"],True),
 ("recruit@gmail.com","Offer","Send your OTP and Aadhaar to confirm",[],True),
 ("hr@acme-jobs.com","Training","Pay the training fee immediately",[],True),
 ("pc@college.edu","Notice","Placement briefing tomorrow in Hall 2",[],False),
 ("prof@college.edu","Exam","Syllabus for the exam is on the portal",[],False),
 ("friend@gmail.com","Weekend","Want to study together?",[],False),
 ("news@company.com","Newsletter","New roles open for students",[],False),
 ("priya@northwind.com","Interview","Interview on 22 Oct 3:00 PM",["northwind.com"],False),
 ("billing@college.edu","Fees","Semester fee notice, pay at the college office",[],False),
]
c = fpc = 0; tpr = n_r = 0
for s, sub, b, k, risky in RISK:
    flagged = assess_risk(s, sub, b, known_domains=k)["score"] >= 30
    if risky: n_r += 1; tpr += flagged
    else: fpc += flagged
print(f"risk        risky_recall={tpr}/{n_r} false_positives={fpc}/{len(RISK)-n_r} (threshold score>=30)")

# --- anomaly model on synthetic history (60 normal + injected odd emails; synthetic, so optimistic) ---
import random
from types import SimpleNamespace as NS
from app.ml import anomaly_scores
random.seed(1)
norm = [NS(id=f"n{i}", received_at=datetime(2026, 10, 1, random.randint(8, 19), tzinfo=timezone.utc), subject=f"Class notes {random.randint(1, 99)}", snippet="See the attached notes for this week " * random.randint(1, 2), sender="prof@college.edu") for i in range(190)]
odd = [NS(id=f"a{i}", received_at=datetime(2026, 10, 1, random.randint(1, 4), tzinfo=timezone.utc), subject="URGENT act now", snippet="Click https://x.co https://y.co immediately last chance 99999", sender="hr@gmail.com") for i in range(10)]
res = anomaly_scores(norm + odd, top=10); hit = sum(i["email_id"].startswith("a") for i in res["items"])
print(f"anomaly     injected=10 in_top10={hit} normal_in_top10={10-hit}")
