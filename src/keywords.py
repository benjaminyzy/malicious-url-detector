# Centralised keyword lists used by the feature extractor and rule engine.

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "signin", "session",
    "wallet", "authenticate", "validation",
]

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "netflix", "instagram", "linkedin",
    "whatsapp", "twitter", "dropbox", "github",
    "maybank", "cimb", "publicbank", "rhb", "hsbc",
]

PRIZE_KEYWORDS = [
    "prize", "winner", "claim", "reward", "lucky",
    "congratulations", "youwon", "you-won", "limited-offer",
    "free-gift", "free-prize",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "bl.ink", "lnkd.in",
    "tr.im", "x.co", "mcaf.ee",
}

# TLDs heavily abused for phishing/malware per Spamhaus and APWG reports
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "loan", "click",
    "work", "country", "stream", "download",
    "racing", "win", "bid", "trade", "date",
    "review", "party", "men", "gdn",
}
