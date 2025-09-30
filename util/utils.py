def parse_input_value(text_val, value_type_str, is_hex):
    if value_type_str == "String":
        return text_val

    if value_type_str == "Array Of Byte":
        if is_hex:
            try:
                return bytes.fromhex(text_val)
            except ValueError:
                try:
                    return bytes.fromhex(text_val.replace(" ", ""))
                except ValueError:
                    raise ValueError(
                        "Invalid Hex Array Of Byte format. Use continuous hex (e.g., AABBCC) or space-separated hex (e.g., AA BB CC)")
        else:
            try:
                return bytes(map(int, text_val.split()))
            except ValueError:
                raise ValueError(
                    "Invalid Decimal Array Of Byte format. Use space-separated integers (e.g., 50 160 223).")
    base = 16 if is_hex else 10
    try:
        if value_type_str in ["Byte", "2 Bytes", "4 Bytes", "8 Bytes"]:
            return int(text_val, base)
        elif value_type_str == "Float":
            if is_hex:
                raise ValueError("Hex input for Float is not directly supported. Enter as decimal")
            return float(text_val)
        elif value_type_str == "Double":
            if is_hex:
                raise ValueError("Hex input for Double is not directly supported. Enter as decimal")
            return float(text_val)
    except ValueError:
        raise ValueError(f"Invalid {value_type_str} format for base {base if is_hex else 'decimal'}")

    return None
