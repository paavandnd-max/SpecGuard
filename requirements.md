# RefundFlow acceptance criteria

- [ ] REQ-001: A refund amount must be greater than zero. (source: demo/refund_flow.py)
- [ ] REQ-002: A refund cannot exceed the amount captured for the order. (source: demo/refund_flow.py)
- [ ] REQ-003: Only paid orders may be refunded. (source: demo/refund_flow.py)
- [ ] REQ-004: Refunds are accepted through 30 days after order creation. (source: demo/refund_flow.py)
- [ ] REQ-005: Digital goods cannot be refunded. (source: demo/refund_flow.py)
- [ ] REQ-006: Reusing an idempotency key returns the original refund record. (source: demo/refund_flow.py)
- [ ] REQ-007: A nonblank reason is required. (source: demo/refund_flow.py)
- [ ] REQ-008: Only USD refunds are supported. (source: demo/refund_flow.py)
- [ ] REQ-009: A new refund starts in the pending state. (source: demo/refund_flow.py)
- [ ] REQ-010: Refund amounts are stored with cent precision. (source: demo/refund_flow.py)

The demo test suite intentionally omits REQ-004, REQ-008, and REQ-010 so the
baseline passes while exposing exactly three unprotected requirements.
