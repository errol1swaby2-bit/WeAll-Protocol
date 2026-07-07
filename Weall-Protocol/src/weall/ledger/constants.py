from __future__ import annotations

"""Genesis v1.5 monetary constants.

Spec anchors (v1.5):
- Fixed supply: 21,000,000 WCN, divisible to 1e-8.
- Consensus/block target interval: 20 seconds.
- Issuance cadence: one 10-minute issuance epoch, equal to 30 blocks at
  the 20-second target interval.
- Initial issuance: 100 WCN per issuance epoch, not per block.
- Halving interval: 105,120 issuance epochs, approximately two years.
- Fees/rewards/economics stay disabled until the Genesis economic lock and
  governance activation path are both satisfied.
"""

# Monetary precision (1 WCN = 1e-8 units)
COIN_DECIMALS: int = 8
COIN: int = 10**COIN_DECIMALS

# Supply cap: 21,000,000 WCN
MAX_SUPPLY_WCN: int = 21_000_000
MAX_SUPPLY: int = MAX_SUPPLY_WCN * COIN

# Consensus/block cadence.  This is separate from monetary issuance cadence.
TARGET_BLOCK_INTERVAL_SECONDS: int = 20

# Issuance cadence.  One epoch is 10 minutes; at 20-second blocks this is 30 blocks.
ISSUANCE_EPOCH_SECONDS: int = 10 * 60
ISSUANCE_EPOCH_BLOCKS: int = ISSUANCE_EPOCH_SECONDS // TARGET_BLOCK_INTERVAL_SECONDS

# Epoch issuance schedule.
INITIAL_ISSUANCE_PER_EPOCH_WCN: int = 100
INITIAL_ISSUANCE_PER_EPOCH: int = INITIAL_ISSUANCE_PER_EPOCH_WCN * COIN

# 2 years of 10-minute issuance epochs: 365 days * 2 * 24 hours * 6 epochs/hour.
HALVING_INTERVAL_ISSUANCE_EPOCHS: int = 105_120

# Actual block count in one halving interval at the v1.5 block cadence.
HALVING_INTERVAL_BLOCKS: int = HALVING_INTERVAL_ISSUANCE_EPOCHS * ISSUANCE_EPOCH_BLOCKS

# Backward-compatible aliases for older imports.  New code should use the
# explicit block-interval and issuance-epoch names above.
TARGET_BLOCK_TIME_SECONDS: int = TARGET_BLOCK_INTERVAL_SECONDS
INITIAL_BLOCK_REWARD_WCN: int = INITIAL_ISSUANCE_PER_EPOCH_WCN
INITIAL_BLOCK_REWARD: int = INITIAL_ISSUANCE_PER_EPOCH

# Reward split: 20% each.  Distribution remains locked with the rest of economics.
REWARD_BUCKETS = ("validators", "operators", "jurors", "creators", "treasury")

# Canonical treasury account id in ledger.accounts
TREASURY_ACCOUNT_ID: str = "TREASURY"

# Internal accounting pool used by system issuance/reward txs.
#
# Rationale:
# - BLOCK_REWARD_MINT credits this pool with epoch issuance.
# - BLOCK_REWARD_DISTRIBUTE and other reward allocations must debit from this
#   pool (and later fee pools) so that reward credits cannot inflate supply.
MINT_POOL_ACCOUNT_ID: str = "MINT_POOL"
