from datetime import date

import pytest

from demo.refund_flow import RefundError, RefundFlow


def flow(**overrides):
    order = {
        "status": "paid",
        "captured_amount": 50.0,
        "created_at": date(2026, 1, 1),
        "digital": False,
        "currency": "USD",
    }
    order.update(overrides)
    return RefundFlow({"o-1": order})


def request(service, **kwargs):
    values = {"order_id": "o-1", "amount": 10.125, "reason": "broken", "idempotency_key": "k-1", "now": date(2026, 1, 10)}
    values.update(kwargs)
    return service.request_refund(**values)


def test_amount_must_be_positive():
    with pytest.raises(RefundError):
        request(flow(), amount=0)


def test_amount_cannot_exceed_capture():
    with pytest.raises(RefundError):
        request(flow(), amount=50.01)


def test_full_capture_amount_is_allowed():
    result = request(flow(), amount=50.0, idempotency_key="full-capture")
    assert result["amount"] == 50.0


def test_only_paid_orders_are_refundable():
    with pytest.raises(RefundError):
        request(flow(status="authorized"))


def test_digital_goods_are_blocked():
    with pytest.raises(RefundError):
        request(flow(digital=True))


def test_duplicate_key_returns_same_record():
    service = flow()
    first = request(service)
    second = request(service, amount=20)
    assert second == first


def test_reason_is_required():
    with pytest.raises(RefundError):
        request(flow(), reason=" ")


def test_new_refunds_are_pending_and_audited():
    service = flow()
    result = request(service)
    assert result["status"] == "pending"
    assert service.audit_log == [{"event": "refund_requested", "order_id": "o-1"}]
