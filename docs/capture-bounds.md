# Dual-Token Capture Time Bounds Specification

This specification defines the dual-token protocol for proving physical capture interval bounds using cryptographic time stamps.

## Protocol Mechanics
1. **Pre-Capture Challenge ($T_1$)**: The capture system requests a time-stamp token over an unpredictable challenge $C_1$ prior to capture.
2. **Media Capture ($M$)**: The sensor records media $M$ and binds $C_1$ to the initial frame/chunk commitment $H(M)$.
3. **Post-Capture Token ($T_2$)**: The system requests a second RFC 3161 token $T_2$ over $H(M) \parallel H(T_1)$.

## Verification
A validator verifies that the media capture event occurred strictly within the time interval $(T_1.\text{time}, T_2.\text{time})$.
