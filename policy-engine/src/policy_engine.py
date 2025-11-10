class PolicyEngine:
    def __init__(self):
        self._policy_map = {
            "high": "AES-256-GCM",
            "medium": "AES-128-GCM",
            "low": "ChaCha20-Poly1305"
        }
        print("Policy Engine initialized.")
        for level, algo in self._policy_map.items():
            print(f"  -> {level.capitalize()} sensitivity maps to: {algo}")

    def select_algorithm(self, sensitivity: str) -> str:
        level = sensitivity.lower().strip()
        algorithm = self._policy_map.get(level)
        if not algorithm:
            raise ValueError(f"Invalid sensitivity level '{sensitivity}'. Valid options are: {list(self._policy_map.keys())}")
        print(f"\nDecision: For '{sensitivity}' sensitivity, selecting algorithm: {algorithm}")
        return algorithm
