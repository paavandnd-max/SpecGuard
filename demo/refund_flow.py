from __future__ import annotations

from datetime import date


class RefundError(ValueError):
    pass


class RefundFlow:
    def __init__(self, orders: dict[str, dict]):
        self.orders = orders
        self._requests: dict[str, dict] = {}
        self.audit_log: list[dict] = []

    def request_refund(
        self,
        order_id: str,
        amount: float,
        reason: str,
        idempotency_key: str,
        now: date,
    ) -> dict:
        order = self.orders.get(order_id)
        if order is None:
            raise RefundError("order not found")
        # specguard: REQ-001
        if amount <= 0:
            raise RefundError("amount must be positive")
        # specguard: REQ-002
        if amount > order["captured_amount"]:
            raise RefundError("amount exceeds captured amount")
        # specguard: REQ-003
        if order["status"] != "paid":
            raise RefundError("order is not paid")
        created = order["created_at"]
        age_days = (now - created).days
        # specguard: REQ-004
        if age_days > 30:
            raise RefundError("refund window expired")
        # specguard: REQ-005
        if order["digital"]:
            raise RefundError("digital goods are not refundable")
        # specguard: REQ-006
        if idempotency_key in self._requests:
            return self._requests[idempotency_key]
        # specguard: REQ-007
        if not reason.strip():
            raise RefundError("reason is required")
        currency = order.get("currency", "USD")
        # specguard: REQ-008
        if currency != "USD":
            raise RefundError("currency is not supported")
        record = {
            "order_id": order_id,
            "amount": amount,
            # specguard: REQ-009
            "status": "pending",
            "reason": reason.strip(),
            "currency": currency,
        }
        # specguard: REQ-010
        record["amount"] = round(record["amount"], 2)
        self._requests[idempotency_key] = record
        self.audit_log.append({"event": "refund_requested", "order_id": order_id})
        return record
