# src/weall/ledger/constants.py
from __future__ import annotations

"""Genesis (v2.1) monetary constants.

Spec anchors (v2.1):
- Fixed supply: 21,000,000 WCN, divisible to 1e-8
- Target block time: 10 minutes
- Initial block reward: 100 WCN
- Halving every two years
- Fees included in rewards
"""

# Monetary precision (1 WCN = 1e-8 units)
COIN_DECIMALS: int = 8
COIN: int = 10**COIN_DECIMALS

# Supply cap: 21,000,000 WCN
MAX_SUPPLY_WCN: int = 21_000_000
MAX_SUPPLY: int = MAX_SUPPLY_WCN * COIN

# Block cadence
TARGET_BLOCK_TIME_SECONDS: int = 600  # 10 minutes

# Reward schedule
INITIAL_BLOCK_REWARD_WCN: int = 100
INITIAL_BLOCK_REWARD: int = INITIAL_BLOCK_REWARD_WCN * COIN

# ~2 years at 10 min blocks: 365 days * 2 * 24 hours * 6 blocks/hour = 105,120
HALVING_INTERVAL_BLOCKS: int = 105_120

# Reward split (v2.1): 20% each
REWARD_BUCKETS = ("validators", "operators", "jurors", "creators", "treasury")

# Canonical treasury account id in ledger.accounts
TREASURY_ACCOUNT_ID: str = "TREASURY"
