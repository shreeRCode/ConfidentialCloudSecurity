class PolicyEngine:
    def __init__(self):
        self._policy_map = {
            "high": "AES-256-GCM",
            "medium": "AES-128-GCM",
            "low": "ChaCha20-Poly1305"
        }
        print("Policy Engine initialized.")
        print(f"  -> High sensitivity maps to: {self._policy_map['high']}")
        print(f"  -> Medium sensitivity maps to: {self._policy_map['medium']}")
        print(f"  -> Low sensitivity maps to: {self._policy_map['low']}")

    def select_algorithm(self, sensitivity: str) -> str:
        level = sensitivity.lower().strip()
        algorithm = self._policy_map.get(level)

        if not algorithm:
            raise ValueError(
                f"Invalid sensitivity level '{sensitivity}'. "
                f"Valid options are: {list(self._policy_map.keys())}"
            )

        print(f"\nDecision: For '{sensitivity}' sensitivity, selecting algorithm: {algorithm}")
        return algorithm