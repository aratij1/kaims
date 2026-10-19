# Detected / Understanding stage review

A read-only sample of the ten most recently updated open incidents found eight WAITING_FOR_HUMAN, one INVESTIGATING with a hypothesis, and one DETECTED with RCA not_started. These are current backend operations-state results, not inferred from the screenshot. Several human-waiting incidents also have scheduled automatic collection jobs. One investigating incident has observed impact but an unconfirmed causal hypothesis.

The detail journey had a real mapping defect: context_ready, requirements_identified and rca_ready were not recognized and could fall back to Detected. Context-ready and requirements-identified now map to Understanding; RCA-ready maps to Root cause. The journey now displays the backend next_action message directly below its heading so waiting for human evidence does not look like silent processing.

The evidence planner routes unknown/unstructured gap categories to explicit validation/review work rather than guessing a connector. Existing missing-evidence and human-validation gates remain. This change does not turn a hypothesis into a grounded RCA, mark impact established, or advance blocked incidents into execution. The earlier queue deferral feature manages capacity; it does not resolve those evidence requirements.

Six regression cases cover the ready, collecting, human-waiting and initial states. Full frontend quality and production build results are in journey-stage-ui-tests.log and journey-stage-ui-build.log.
