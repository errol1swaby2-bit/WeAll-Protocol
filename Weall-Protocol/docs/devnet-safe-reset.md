# Issue 68: controlled-devnet reset and local IPFS recovery

This change separates destructive, operator-requested devnet resets from
non-destructive IPFS recovery detection. Do not run reset commands against
a ledger or IPFS repository you intend to preserve.

## Default reset

From the backend checkout, explicitly invoking
bash scripts/devnet_reset_state.sh resets the checkout's own .weall-devnet
directory. It calls devnet_safe_paths.py, which rejects symlinked path
components and uses Linux fd-relative, symlink-resistant deletion.

Custom WEALL_DEVNET_DIR locations are not automatically trusted even if the
basename is .weall-devnet. To intentionally reset a custom disposable
directory, set both WEALL_DEVNET_RESET_ALLOWED_PARENT to the EXACT absolute
path of its existing parent and
WEALL_DEVNET_RESET_CONFIRM=I_CONFIRM_DELETE_CUSTOM_DEVNET.
The helper rejects root/home/common system directories, parent traversal,
and symlink path components. Do not leave these confirmation variables
permanently enabled.

## IPFS storage

The rehearsal launcher permits auto-managed local storage only in
the reserved ipfs_partition or ipfs direct child of the configured devnet
directory; accounts, node state and arbitrary child names are refused. The helper checks the
existing partition, blocks, SHARDING and temp paths for symlinks before
any mkdir/chmod. A corrupt blocks tree without SHARDING now fails startup
without deleting the repository. For an independently managed external
IPFS daemon, use WEALL_LOCAL_REHEARSAL_START_IPFS=0 rather than an
auto-managed partition override.

## Validation and limits

The dedicated CI job performs temporary-directory-only positive and
negative tests for custom path approval, unsafe parents, symlinks, missing
SHARDING, and no unintended external-file deletion. It does not run the
full two-node rehearsal or touch persistent operator/validator data.

This closes neither protocol consensus proof nor constitutional authority.
The frontend cache cleanup and IPFS port-repair behavior of the rehearsal
launcher are independent operational review boundaries.
