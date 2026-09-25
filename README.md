# SBT-DF203-Lab9: WEP40 Wireless Packet Decryption and Aircrack Forensics

A formal digital forensics investigation analyzing IEEE 802.11 wireless frame structures, WEP/RC4 cryptographic vulnerabilities, and offline traffic decryption. Executed against the historical CodeGate CTF "Good Crypto" capture, this lab demonstrates Initialization Vector (IV) collision tracking, Aircrack-ng secret key recovery, Airdecap-ng payload decryption, and Layer 3–7 endpoint/object carving using `tshark` and `foremost`.

---

## 📌 Investigation Overview

- **Lead Examiner:** Nebeuwa Ifeanyichukwu Raphael
- **Course & Lab:** SBT-DF203 — Basic Networking Skills for Digital Forensics (Lab 9)
- **Primary Tools:** `aircrack-ng`, `airdecap-ng`, `tshark`, `wireshark`, `foremost`, `binwalk`, `xz-utils`, `sha256sum`
- **Dataset:** CodeGate CTF 2015 "Good Crypto" historical wireless capture (`file.xz`)

### Key Analytical Findings
- **Evidence Preservation:** Decompressed and verified working copy integrity (`working/file_working`) with full SHA-256 chain-of-custody tracking.
- **802.11 Frame Inventory:** Categorized Management (`type 0`), Control (`type 1`), and Data (`type 2`) frames. Isolated protected data payloads (`wlan.fc.protected == 1`).
- **WEP40 Weakness Verification:** Identified massive Initialization Vector (IV) reuse across captured frames. The 24-bit IV length coupled with static RC4 key usage enabled deterministic keystream recovery.
- **Key Recovery & Decryption:** Verified the 40-bit WEP secret key (`A4:3D:F6:F3:74`) using `aircrack-ng`. Applied `airdecap-ng -w A43DF6F374` to produce an unencrypted output capture (`file_working-dec.pcap`).
- **Endpoint & Artifact Carving:** Extracted Ethernet/IP endpoints, TCP session flows, and carved higher-layer transferred objects (HTML and images) using `tshark --export-objects` and `foremost`.

---

## 📁 Repository Structure

```text
SBT-DF203-Lab9/
├── evidence/
│   └── file.xz                        # Compressed original CTF wireless capture
├── working/
│   ├── file_working.xz                # Working compressed evidence copy
│   ├── file_working                   # Decompressed raw 802.11 capture
│   └── file_working-dec.pcap          # Decrypted post-airdecap capture
├── exported/
│   ├── http_objects/                  # Objects extracted via TShark HTTP export
│   └── foremost/                      # Raw carved files from Foremost
├── reports/
│   ├── file_xz_sha256.txt             # Original file hash log
│   ├── working_hashes.txt             # Decompressed evidence SHA-256 hashes
│   ├── capinfos.txt                   # Capture file metadata dump
│   ├── protocol_hierarchy.txt         # IEEE 802.11 protocol hierarchy output
│   ├── wlan_frame_sample.tsv          # Frame type and MAC address breakdown
│   ├── wep_protected_frames.tsv       # Filtered WEP protected frame details
│   ├── repeated_iv_summary.txt        # Highlighting IV collision occurrences
│   ├── aircrack_output.txt            # Key recovery output log
│   ├── validated_wep40_key_masked.txt # Documented 40-bit hex key
│   ├── airdecap_output.txt            # Decryption operation summary
│   ├── decrypted_files_inventory.txt  # Post-decryption file listing
│   ├── all_working_file_hashes.txt    # Hashes of all working/decrypted files
│   ├── decrypted_capture_path.txt     # Target path for decrypted analysis
│   ├── ethernet_endpoints.txt         # Extracted MAC addresses
│   ├── ip_endpoints.txt               # Extracted IP endpoints
│   ├── tcp_conversations.txt          # Reconstructed TCP streams
│   ├── ip_mac_mapping_sample.tsv      # Layer 2 to Layer 3 address mapping
│   ├── http_export_log.txt            # TShark object export results
│   ├── foremost_log.txt               # Foremost carving execution log
│   ├── exported_file_types.txt        # File types of carved objects
│   └── exported_file_hashes.txt       # Hashes of all carved/extracted objects
└── README.md
```

## ⚙️ Execution & Methodology

**1. Evidence Extraction & Hash Chain Setup**

Establish directory structure, fetch original CTF evidence, and log SHA-256 checksums:

```Bash
mkdir -p ~/SBT-DF203-Lab9/{evidence,working,exported,reports,screenshots,scripts}
cd ~/SBT-DF203-Lab9

# Download historical CTF evidence
wget -O evidence/file.xz '[https://raw.githubusercontent.com/ctfs/write-ups-2015/master/codegate-ctf-2015/programming/good-crypto/file.xz](https://raw.githubusercontent.com/ctfs/write-ups-2015/master/codegate-ctf-2015/programming/good-crypto/file.xz)'
sha256sum evidence/file.xz | tee reports/file_xz_sha256.txt

# Decompress and calculate working hashes
cp --preserve=timestamps evidence/file.xz working/file_working.xz
unxz -k working/file_working.xz
file working/file_working
sha256sum working/file_working.xz working/file_working | tee reports/working_hashes.txt
```

**2. Wireless Traffic Profiling & WEP Inspection**

Examine frame distributions, BSSID parameters, and IV reuse metrics:

```Bash
CAP=working/file_working

# Capture statistics and frame taxonomy
capinfos "$CAP" | tee reports/capinfos.txt
tshark -r "$CAP" -q -z io,phs | tee reports/protocol_hierarchy.txt

# Sample 802.11 frames (Management, Control, Data)
tshark -r "$CAP" -Y 'wlan' -T fields \
  -e frame.number -e frame.time -e wlan.fc.type -e wlan.fc.subtype -e wlan.sa -e wlan.da -e wlan.bssid \
  | head -n 100 | tee reports/wlan_frame_sample.tsv

# Extract protected frames and track IV duplication
tshark -r "$CAP" -Y 'wlan.fc.protected==1' -T fields \
  -e frame.number -e frame.time_epoch -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.wep.iv -e wlan.wep.key \
  | head -n 200 | tee reports/wep_protected_frames.tsv

tshark -r "$CAP" -Y 'wlan.fc.protected==1' -T fields -e wlan.wep.iv \
  | sort | uniq -c | sort -nr | head -n 30 | tee reports/repeated_iv_summary.txt
```

**3. Secret Key Recovery & Offline Decryption**

Execute aircrack-ng to isolate the WEP key and apply airdecap-ng to decrypt encrypted frames:

```Bash
# Recover 40-bit WEP key
aircrack-ng "$CAP" | tee reports/aircrack_output.txt
printf 'A4:3D:F6:F3:74\n' | tee reports/validated_wep40_key_masked.txt

# Decrypt capture (Remove colons from key for airdecap-ng)
cd working
airdecap-ng -w A43DF6F374 file_working | tee ../reports/airdecap_output.txt
cd ..

# Verify decrypted capture creation & hashing
find working -maxdepth 1 -type f | tee reports/decrypted_files_inventory.txt
sha256sum working/* | tee reports/all_working_file_hashes.txt
```

**4. Post-Decryption Forensics & Endpoint Carving**

Analyze higher-layer protocols (IP/TCP/HTTP) and carve transferred artifacts:

```Bash
DEC=$(find working -maxdepth 1 -type f -name "*-dec*" | head -n 1)
echo "Decrypted capture: $DEC" | tee reports/decrypted_capture_path.txt

# Endpoint & Conversation Analysis
tshark -r "$DEC" -q -z endpoints,eth | tee reports/ethernet_endpoints.txt
tshark -r "$DEC" -q -z endpoints,ip | tee reports/ip_endpoints.txt
tshark -r "$DEC" -q -z conv,tcp | tee reports/tcp_conversations.txt

tshark -r "$DEC" -Y 'ip' -T fields \
  -e frame.number -e wlan.sa -e wlan.da -e ip.src -e ip.dst -e _ws.col.Protocol \
  | head -n 200 | tee reports/ip_mac_mapping_sample.tsv

# Object Carving
mkdir -p exported/http_objects exported/foremost
tshark -r "$DEC" --export-objects http,exported/http_objects 2>&1 | tee reports/http_export_log.txt
foremost -i "$DEC" -o exported/foremost | tee reports/foremost_log.txt

# Hash all extracted evidence
find exported -type f -exec file {} \; | tee reports/exported_file_types.txt
find exported -type f -exec sha256sum {} \; | tee reports/exported_file_hashes.txt
```






