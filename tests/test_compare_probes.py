import unittest

from _helpers import ROOT  # noqa: F401
import compare_probes as cp


def doc(results, host="h", mode="A", role="anon"):
    return {"meta": {"host": host, "mode": mode, "role": role}, "results": results}


def r(pid, cls, expect="DENY"):
    return {"id": pid, "classification": cls, "expect": expect}


class CompareTests(unittest.TestCase):
    def test_verified_requires_fix_and_regression_probe(self):
        before = doc([r("read:t", "LEAK"), r("read:mine", "ALLOWED", "ALLOW")])
        after = doc([r("read:t", "BLOCKED-RLS"), r("read:mine", "ALLOWED", "ALLOW")])
        self.assertEqual(cp.compare(before, after)["status"], "VERIFIED")

    def test_fix_without_regression_probe_is_not_verified(self):
        res = cp.compare(doc([r("read:t", "LEAK")]), doc([r("read:t", "BLOCKED-GRANT")]))
        self.assertEqual(res["status"], "FIX-APPLIED-NOT-VERIFIED")
        self.assertTrue(any("regression probe" in x for x in res["reasons"]))

    def test_still_leaking_fails(self):
        res = cp.compare(doc([r("read:t", "LEAK")]), doc([r("read:t", "LEAK")]))
        self.assertEqual(res["status"], "FAILED")

    def test_newly_leaking_fails(self):
        res = cp.compare(doc([r("read:t", "BLOCKED-RLS")]), doc([r("read:t", "LEAK")]))
        self.assertEqual(res["rows"][0]["verdict"], "NEWLY-LEAKING")
        self.assertEqual(res["status"], "FAILED")

    def test_regression_of_legitimate_flow_fails(self):
        before = doc([r("read:t", "LEAK"), r("read:mine", "ALLOWED", "ALLOW")])
        after = doc([r("read:t", "BLOCKED-RLS"), r("read:mine", "REGRESSION", "ALLOW")])
        res = cp.compare(before, after)
        self.assertEqual(res["status"], "FAILED")

    def test_inconclusive_never_counts_as_fixed(self):
        res = cp.compare(doc([r("read:t", "LEAK")]), doc([r("read:t", "INCONCLUSIVE")]))
        self.assertEqual(res["rows"][0]["verdict"], "UNVERIFIED")
        self.assertEqual(res["status"], "FIX-APPLIED-NOT-VERIFIED")

    def test_unlike_runs_block_verified(self):
        before = doc([r("read:t", "LEAK"), r("read:mine", "ALLOWED", "ALLOW")], host="a")
        after = doc([r("read:t", "BLOCKED-RLS"), r("read:mine", "ALLOWED", "ALLOW")], host="b")
        res = cp.compare(before, after)
        self.assertEqual(res["status"], "FIX-APPLIED-NOT-VERIFIED")
        self.assertTrue(res["warnings"])

    def test_missing_probe(self):
        res = cp.compare(doc([r("read:a", "LEAK")]), doc([]))
        self.assertEqual(res["rows"][0]["verdict"], "MISSING")


if __name__ == "__main__":
    unittest.main()
