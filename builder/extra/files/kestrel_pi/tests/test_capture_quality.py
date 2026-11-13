"""Tests for the capture-quality grading (pure) and the store producer."""

from kestrel_pi import capture_quality as cq
from kestrel_pi.capture import CaptureInterface


def _pmkid(ap="aabbccddee01", essid="Net"):
    # WPA*01*PMKID*AP*STA*ESSID
    return "WPA*01*%s*%s*112233445566*%s" % ("a" * 32, ap, essid.encode().hex())


def _eapol(ap="aabbccddee01", essid="Net", pair="02"):
    # WPA*02*MIC*AP*STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
    return "WPA*02*%s*%s*112233445566*%s*%s*%s*%s" % (
        "b" * 32, ap, essid.encode().hex(), "c" * 64, "d" * 10, pair)


# --- the pure classifier ----------------------------------------------------
def test_signal_reads_type_and_message_pair():
    assert cq.signal(_pmkid()).kind == "pmkid"
    s = cq.signal(_eapol(pair="03"))        # M2+M3 from M3 -> AP-confirmed
    assert s.kind == "eapol" and s.ap_confirmed is True
    s = cq.signal(_eapol(pair="00"))        # M1+M2 from M2 -> not confirmed
    assert s.kind == "eapol" and s.ap_confirmed is False
    assert cq.signal("garbage").kind == ""
    assert cq.signal("").kind == ""


def test_message_pair_bad_hex_is_not_confirmed():
    assert cq.signal(_eapol(pair="zz")).ap_confirmed is False


def test_grades_and_scores_rank_pmkid_then_handshake():
    both = cq.classify_lines([_pmkid(), _eapol()])
    assert both.grade == "pmkid+handshake" and both.score == 3
    pmkid = cq.classify_lines([_pmkid()])
    assert pmkid.grade == "pmkid" and pmkid.score == 2
    hs = cq.classify_lines([_eapol(pair="00")])
    assert hs.grade == "handshake" and hs.score == 1
    assert "client-side" in hs.note                 # honest about M1+M2
    hs_ok = cq.classify_lines([_eapol(pair="04")])  # M3+M4 -> AP-confirmed
    assert hs_ok.ap_confirmed is True and "AP-confirmed" in hs_ok.note
    assert cq.classify_lines([]).grade == "none"
    assert cq.classify_lines(["garbage"]).grade == "none"


def test_scores_let_the_cracker_order_targets():
    # higher score = better material, so a sort descending puts PMKID/both first
    grades = [cq.classify_lines(ls).grade for ls in (
        [_eapol(pair="00")], [_pmkid(), _eapol()], [_pmkid()])]
    ordered = sorted(grades, key=lambda g: -cq.GRADE_SCORE[g])
    assert ordered == ["pmkid+handshake", "pmkid", "handshake"]


def test_summarize_counts_crackable_and_picks_best():
    qs = [cq.classify_lines([_eapol(pair="00")]),
          cq.classify_lines([_pmkid(), _eapol()]),
          cq.classify_lines([])]              # the 'none' is not counted
    count, best = cq.summarize(qs)
    assert count == 2 and best == "pmkid+handshake"
    assert cq.summarize([]) == (0, None)


# --- the store producer -----------------------------------------------------
def test_access_point_quality_groups_by_bssid(tmp_path):
    store = tmp_path / "cap"
    store.mkdir()
    (store / "a.hc22000").write_text("\n".join([
        _pmkid(ap="aabbccddee01", essid="Alpha"),
        _eapol(ap="aabbccddee01", essid="Alpha", pair="03"),  # same AP: both
        _eapol(ap="aabbccddee02", essid="Beta", pair="00"),   # handshake only
    ]) + "\n")
    cap = CaptureInterface(str(store))
    q = cap.access_point_quality()
    assert q["AA:BB:CC:DD:EE:01"].grade == "pmkid+handshake"
    assert q["AA:BB:CC:DD:EE:01"].ap_confirmed is True
    assert q["AA:BB:CC:DD:EE:02"].grade == "handshake"
    assert q["AA:BB:CC:DD:EE:02"].ap_confirmed is False


def test_access_point_quality_empty_store(tmp_path):
    store = tmp_path / "cap"
    store.mkdir()
    assert CaptureInterface(str(store)).access_point_quality() == {}
