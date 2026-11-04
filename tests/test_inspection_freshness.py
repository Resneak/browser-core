import browser_core.inspection_freshness as freshness


def test_refresh_without_new_rows_is_not_progress_even_when_source_has_more_bytes(monkeypatch):
    now=[10.0]
    monkeypatch.setattr(freshness.time,'monotonic',lambda:now[0])
    tracker=freshness.InspectionFreshness()
    initial=tracker.observe([],0,finalized=False,generation=0)
    assert initial['newly_visible_observations'] is None
    assert initial['seconds_since_progress'] is None and initial['pending_events_possible']
    now[0]=13
    quiet=tracker.observe([],0,finalized=False,generation=0)
    assert quiet['newly_visible_observations']==0 and quiet['last_progress_at_utc'] is None
    first=tracker.observe([{'ts':9007199254740993}],1,finalized=False,generation=0)
    assert first['newly_visible_observations']==1 and first['seconds_since_progress']==0
    assert first['latest_event_timestamp_ns']=='9007199254740993'
    now[0]=18
    quiet=tracker.observe([{'ts':9007199254740993}],1,finalized=False,generation=0)
    assert quiet['newly_visible_observations']==0 and quiet['seconds_since_progress']==5
    assert quiet['last_progress_at_utc']==first['last_progress_at_utc']
    # A late-sorted observation is still progress even if latest timestamp is unchanged.
    late=tracker.observe([{'ts':9007199254740993},{'ts':42}],2,finalized=False,generation=0)
    assert late['newly_visible_observations']==1 and late['seconds_since_progress']==0
    done=tracker.observe([{'ts':9007199254740993}],2,finalized=True,generation=0)
    assert not done['pending_events_possible'] and not done['proves_capture_complete']


def test_decoder_replay_and_population_reduction_reset_comparison():
    tracker=freshness.InspectionFreshness()
    tracker.observe([{'ts':10}],50,finalized=False,generation=0)
    replay=tracker.observe([],0,finalized=False,generation=1)
    assert replay['comparison_reset'] and replay['newly_visible_observations'] is None
    assert replay['seconds_since_progress'] is None
    tracker.observe([{'ts':12}],60,finalized=False,generation=1)
    reduced=tracker.observe([{'ts':10}],50,finalized=False,generation=1)
    assert reduced['comparison_reset'] and reduced['newly_visible_observations'] is None
