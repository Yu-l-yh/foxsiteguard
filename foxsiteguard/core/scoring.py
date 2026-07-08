"""
Risk scoring engine based on multiple feature signals.
"""
def score(features: dict) -> dict:
    """
    Calculate a risk score from extracted features.

    Args:
        features: dict with keys 'ioc', 'similar', 'age', 'ssl_valid', 'impersonation'

    Returns:
        score (int): 0-100
        level (str): SAFE / MEDIUM RISK / HIGH RISK / CRITICAL
        reasons (list[str]): explanation of contributing factors
    """
    total = 0
    reasons = []
    weight = features.get("weight", 1.0)

    # IOC — highest priority, short-circuits
    ioc_result = features.get("ioc", {})
    if isinstance(ioc_result, dict) and ioc_result.get("matched"):
        return {
            "score": 100,
            "level": "CRITICAL",
            "reasons": [f'IOC matched: {ioc_result.get("match", "unknown")}'],
        }

    # Domain similarity
    similar = features.get("similar", 0)
    if similar > 0.95:
        total += 40
        reasons.append("Very high similarity to official domain")
    elif similar > 0.85:
        total += 20
        reasons.append("Possible domain spoofing (similar to official)")

    # Impersonation pattern detection
    impersonation = features.get("impersonation", {})
    if isinstance(impersonation, dict):
        imp_score = impersonation.get("score", 0)
        brand = impersonation.get("brand_match", "")
        prefix = impersonation.get("prefix_used", "")
        if prefix and brand:
            total += 35
            reasons.append(f"Impersonation detected: [{prefix}-{brand}] pattern")
        elif brand:
            total += 20
            reasons.append(f"Domain contains brand name: {brand}")

    # Domain age
    age = features.get("age", 9999)
    if age < 1:
        total += 50
        reasons.append("Domain created today")
    elif age < 7:
        total += 40
        reasons.append("Very new domain (<7 days)")
    elif age < 30:
        total += 20
        reasons.append("New domain (<30 days)")

    # SSL anomalies
    ssl_valid = features.get("ssl_valid", False)
    if not ssl_valid:
        total += 30
        reasons.append("Invalid or mismatched SSL certificate")

    # Apply weight and clamp
    total = int(total * weight)
    if total > 100:
        total = 100

    # Level classification
    if total >= 80:
        level = "HIGH RISK"
    elif total >= 50:
        level = "MEDIUM RISK"
    else:
        level = "SAFE"

    return {
        "score": total,
        "level": level,
        "reasons": reasons,
    }
