from __future__ import annotations

ALLOWED_AUDIT_METADATA = {
    "code", "name", "telegram_id", "mode", "expected_ip_cidrs", "active",
    "enabled", "cooldown_minutes", "status", "allowed_ip_cidrs", "automatic",
    "ip", "method", "owner_paused", "central_status", "report", "event",
    "recipient_count",
}


def audit_metadata(values) -> dict:
    """Keep control audit rows free of POS/business payloads and credentials."""
    if not isinstance(values, dict):
        return {}
    result = {}
    for raw_key, value in list(values.items())[:40]:
        key = str(raw_key)
        if key not in ALLOWED_AUDIT_METADATA:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value[:300] if isinstance(value, str) else value
        elif isinstance(value, (list, tuple)):
            result[key] = [
                item[:160] if isinstance(item, str) else item
                for item in value[:100]
                if isinstance(item, (str, int, float, bool)) or item is None
            ]
    return result


def report_params(values) -> dict:
    if not isinstance(values, dict):
        return {}
    return {
        key: str(values.get(key, ""))[:10]
        for key in ("date_from", "date_to")
        if key in values
    }


def command_payload(command: str, values) -> dict:
    """Pass only fields understood by the local command executor."""
    if not isinstance(values, dict):
        return {}
    allowed = {
        "staff.create": {"first_name", "last_name", "username", "password", "role"},
        "staff.toggle": {"member_id"},
        "staff.password_reset": {"member_id"},
        "staff.update_role": {"member_id", "role"},
        "staff.qr": {"member_id", "rotate"},
        "lan.update": {"client_id", "name", "mode", "active"},
    }.get(command, set())
    if command == "settings.update":
        incoming = values.get("settings") if isinstance(values.get("settings"), dict) else {}
        setting_keys = {
            "receipt_printer_name", "label_printer_name", "receipt_width_mm",
            "auto_print_receipt", "receipt_qr_mode", "receipt_qr_template",
            "receipt_footer", "label_size", "label_layout", "label_order",
            "label_columns", "label_show_price", "label_show_sku", "label_show_store",
        }
        return {"settings": {
            key: value[:300] if isinstance(value, str) else value
            for key, value in incoming.items()
            if key in setting_keys and isinstance(value, (str, int, float, bool))
        }}
    return {
        key: value[:300] if isinstance(value, str) else value
        for key, value in values.items()
        if key in allowed and isinstance(value, (str, int, float, bool))
    }
