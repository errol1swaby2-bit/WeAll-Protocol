# M2 media interruption and reviewer replacement rehearsal

Run `scripts/run_m2_media_rehearsal.sh` after the live actor manifest has been created.

The rehearsal is successful only if:

1. An assigned reviewer declines and is replaced deterministically.
2. The replacement cannot accept before receiving a case-key envelope.
3. Camera denial and WebRTC disconnection do not generate civic transactions.
4. Attendance remains a separate signed transaction.
5. Verdict controls remain locked until attendance is confirmed.
6. Signaling restart leaves the canonical live case unchanged.
7. The final receipt is identical after node restart and replay.

Store sanitized output under `artifacts/m2-closure/media/`. Raw media and private keys are prohibited.
