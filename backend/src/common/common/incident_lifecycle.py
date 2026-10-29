from __future__ import annotations

from enum import StrEnum


class IncidentLifecycleState(StrEnum):
    DETECTED = "DETECTED"
    REQUIREMENTS_IDENTIFIED = "REQUIREMENTS_IDENTIFIED"
    COLLECTING = "COLLECTING"
    WAITING_FOR_HUMAN = "WAITING_FOR_HUMAN"
    CONTEXT_READY = "CONTEXT_READY"
    INVESTIGATING = "INVESTIGATING"
    RCA_READY = "RCA_READY"
    PLAN_READY = "PLAN_READY"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VALIDATING = "VALIDATING"
    CLOSED = "CLOSED"
    COLLECTION_BLOCKED = "COLLECTION_BLOCKED"
    INVESTIGATION_FAILED = "INVESTIGATION_FAILED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    ESCALATED = "ESCALATED"


TERMINAL_INCIDENT_STATES = frozenset({IncidentLifecycleState.CLOSED})
FAILURE_INCIDENT_STATES = frozenset({
    IncidentLifecycleState.COLLECTION_BLOCKED,
    IncidentLifecycleState.INVESTIGATION_FAILED,
    IncidentLifecycleState.EXECUTION_FAILED,
    IncidentLifecycleState.VALIDATION_FAILED,
    IncidentLifecycleState.ESCALATED,
})

_FORWARD = (
    IncidentLifecycleState.DETECTED,
    IncidentLifecycleState.REQUIREMENTS_IDENTIFIED,
    IncidentLifecycleState.COLLECTING,
    IncidentLifecycleState.CONTEXT_READY,
    IncidentLifecycleState.INVESTIGATING,
    IncidentLifecycleState.RCA_READY,
    IncidentLifecycleState.PLAN_READY,
    IncidentLifecycleState.AWAITING_APPROVAL,
    IncidentLifecycleState.EXECUTING,
    IncidentLifecycleState.VALIDATING,
    IncidentLifecycleState.CLOSED,
)
ALLOWED_INCIDENT_TRANSITIONS = {
    state: frozenset({_FORWARD[index + 1], *FAILURE_INCIDENT_STATES})
    for index, state in enumerate(_FORWARD[:-1])
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.DETECTED] |= {
    IncidentLifecycleState.COLLECTING,
    IncidentLifecycleState.WAITING_FOR_HUMAN,
    IncidentLifecycleState.CONTEXT_READY,
    IncidentLifecycleState.INVESTIGATING,
    IncidentLifecycleState.RCA_READY,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.REQUIREMENTS_IDENTIFIED] |= {
    IncidentLifecycleState.WAITING_FOR_HUMAN,
    IncidentLifecycleState.CONTEXT_READY,
    IncidentLifecycleState.INVESTIGATING,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.COLLECTING] |= {
    IncidentLifecycleState.WAITING_FOR_HUMAN,
    IncidentLifecycleState.INVESTIGATING,
    IncidentLifecycleState.RCA_READY,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.WAITING_FOR_HUMAN] = frozenset({
    IncidentLifecycleState.COLLECTING,
    IncidentLifecycleState.CONTEXT_READY,
    IncidentLifecycleState.INVESTIGATING,
    IncidentLifecycleState.RCA_READY,
    IncidentLifecycleState.COLLECTION_BLOCKED,
    IncidentLifecycleState.ESCALATED,
})
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.CONTEXT_READY] |= {
    IncidentLifecycleState.WAITING_FOR_HUMAN,
    IncidentLifecycleState.RCA_READY,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.INVESTIGATING] |= {
    IncidentLifecycleState.WAITING_FOR_HUMAN,
    IncidentLifecycleState.COLLECTING,
    IncidentLifecycleState.REQUIREMENTS_IDENTIFIED,
    IncidentLifecycleState.RCA_READY,
    IncidentLifecycleState.AWAITING_APPROVAL,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.RCA_READY] |= {
    IncidentLifecycleState.AWAITING_APPROVAL,
    IncidentLifecycleState.WAITING_FOR_HUMAN,
    IncidentLifecycleState.EXECUTING,
    IncidentLifecycleState.CLOSED,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.PLAN_READY] |= {
    IncidentLifecycleState.EXECUTING,
    IncidentLifecycleState.CLOSED,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.AWAITING_APPROVAL] |= {
    IncidentLifecycleState.INVESTIGATING,
    IncidentLifecycleState.EXECUTING,
    IncidentLifecycleState.VALIDATING,
    IncidentLifecycleState.CLOSED,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.EXECUTING] |= {
    IncidentLifecycleState.CLOSED,
}
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.COLLECTION_BLOCKED] = frozenset({
    IncidentLifecycleState.COLLECTING,
    IncidentLifecycleState.WAITING_FOR_HUMAN,
    IncidentLifecycleState.CONTEXT_READY,
    IncidentLifecycleState.INVESTIGATING,
    IncidentLifecycleState.RCA_READY,
    IncidentLifecycleState.ESCALATED,
})
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.INVESTIGATION_FAILED] = frozenset({
    IncidentLifecycleState.INVESTIGATING, IncidentLifecycleState.ESCALATED,
})
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.EXECUTION_FAILED] = frozenset({
    IncidentLifecycleState.EXECUTING, IncidentLifecycleState.VALIDATING,
    IncidentLifecycleState.ESCALATED,
})
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.VALIDATION_FAILED] = frozenset({
    IncidentLifecycleState.EXECUTING, IncidentLifecycleState.VALIDATING,
    IncidentLifecycleState.ESCALATED,
})
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.ESCALATED] = frozenset()
ALLOWED_INCIDENT_TRANSITIONS[IncidentLifecycleState.CLOSED] = frozenset()


def validate_incident_transition(current: str, target: str) -> tuple[IncidentLifecycleState, IncidentLifecycleState]:
    current_state = IncidentLifecycleState(current)
    target_state = IncidentLifecycleState(target)
    if target_state not in ALLOWED_INCIDENT_TRANSITIONS[current_state]:
        raise ValueError(f"incident lifecycle transition {current_state.value}->{target_state.value} is not allowed")
    return current_state, target_state
