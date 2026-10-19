from scripts.check_schema_drift import diff_schema


def test_catches_a_column_the_model_declares_but_the_live_table_lacks() -> None:
    """Reproduces the exact bug: IncidentProjectionRecord declared created_at
    via TimestampMixin, but the live table has never had that column.
    """
    modeled = {"incident_projections": {"incident_id", "status", "created_at", "updated_at"}}
    live = {"incident_projections": {"incident_id", "status", "updated_at"}}

    missing_tables, missing_columns, extra_columns = diff_schema(modeled, live)

    assert missing_tables == []
    assert missing_columns == {"incident_projections": {"created_at"}}
    assert extra_columns == {}


def test_reports_extra_live_columns_without_failing() -> None:
    """A column the live table has but no model declares is informational,
    not a broken build -- legacy or forward-compatible columns are normal.
    """
    modeled = {"approvals": {"id", "decision"}}
    live = {"approvals": {"id", "decision", "legacy_notes"}}

    missing_tables, missing_columns, extra_columns = diff_schema(modeled, live)

    assert missing_tables == []
    assert missing_columns == {}
    assert extra_columns == {"approvals": {"legacy_notes"}}


def test_catches_a_model_with_no_backing_table() -> None:
    modeled = {"incident_projections": {"incident_id"}, "ghost_table": {"id"}}
    live = {"incident_projections": {"incident_id"}}

    missing_tables, missing_columns, extra_columns = diff_schema(modeled, live)

    assert missing_tables == ["ghost_table"]
    assert missing_columns == {}


def test_clean_schema_reports_nothing() -> None:
    modeled = {"approvals": {"id", "decision"}}
    live = {"approvals": {"id", "decision"}}

    missing_tables, missing_columns, extra_columns = diff_schema(modeled, live)

    assert (missing_tables, missing_columns, extra_columns) == ([], {}, {})


def test_detects_missing_composite_uniqueness_even_when_each_column_is_indexed():
    from scripts.check_schema_drift import diff_unique_keys

    modeled = {"incidents": {("tenant_id", "id")}}
    assert diff_unique_keys(modeled, {"incidents": {("id",)}}) == modeled
    assert diff_unique_keys(modeled, {"incidents": {("tenant_id", "id")}}) == {}
