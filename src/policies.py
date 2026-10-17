from typing import Dict, Any

class RedactionPolicy:
    def __init__(self, default_strategy: str = "LABEL"):
        self.default_strategy = default_strategy
        # Definición de estrategias por tipo de entidad
        # Opciones: "LABEL" ([CURP_REDACTED]), "MASK" (X****1234), "ANONYMIZE" ([PERSONA])
        self.rules = {
            "CURP": "LABEL",
            "RFC": "LABEL",
            "EMAIL": "LABEL",
            "PHONE": "MASK",
            "NAME": "LABEL"
        }

    def apply_policy(self, entity_type: str, text: str) -> str:
        strategy = self.rules.get(entity_type, self.default_strategy)

        if strategy == "LABEL":
            return f"[{entity_type}_REDACTED]"
        
        elif strategy == "MASK":
            # Si es un teléfono o cadena larga, oculta dejando visibles solo los últimos 4 dígitos
            if len(text) > 4:
                return "*" * (len(text) - 4) + text[-4:]
            return "*****"
            
        elif strategy == "HASH":
            # Keyed pseudonym (HMAC-SHA-512 by default, see crypto_config).
            # An unkeyed hash of a CURP/phone can be reversed by brute force.
            import hmac
            from . import crypto_config
            digest = hmac.new(crypto_config.hmac_key(), text.encode("utf-8"),
                              crypto_config.hash_alg()).hexdigest()
            return f"[{entity_type}_{digest[:16]}]"

        return "[PII_REDACTED]"