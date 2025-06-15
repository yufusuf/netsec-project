from scapy.all import rdpcap
import matplotlib.pyplot as plt
import numpy as np


def read_pcap(filename, max_packets=140):
    # 1) Read all packets from a file
    packets = rdpcap(filename)

    stamps = []
    # 2) Iterate and inspect
    for pkt in packets:
        # Print a one‐line summary (timestamp, layers, lengths…)
        # If you want raw layers, for example IP/TCP:
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            for option in tcp.options:
                if option[0] == "Timestamp":
                    tsval = option[1][0]
                    stamps.append(tsval)

    stamps = np.array(stamps)
    print(f"{filename} Number of tcp timestamps found: {len(stamps)}")
    stamps -= stamps[0]  # Normalize to start from 0
    stamps[0] = 0
    data = stamps[5:max_packets + 5]  # Limit to first 1000 timestamps for plotting
    return data


def read_pcap_realstamps(filename, max_packets=140):
    packets = rdpcap(filename)

    if not packets:
        raise ValueError("empty pcap")

    base = packets[0].time              # keep full Decimal here
    stamps = []

    for pkt in packets:
        if pkt.haslayer("TCP"):
            stamps.append(float(pkt.time - base))   # *now* cast

    stamps = np.asarray(stamps, dtype=np.float64)
    data = stamps[5: max_packets + 5] * 1000  # convert to milliseconds
    print(f"{filename}: {len(stamps)} TCP capture‑time stamps loaded")
    return data


# load and diff
# stamps_covert_s = read_pcap("capture_covert_s.pcap")
stamps_covert = read_pcap("capture_covert.pcap")
stamps_normal = read_pcap("capture_normal.pcap")
# stamps_normal = read_pcap("capture_normal.pcap")
# stamps_covert_pcap = read_pcap_realstamps("capture_covert.pcap")
# stamps_normal_pcap = read_pcap_realstamps("capture_normal.pcap")
stamps_covert_delayed2 = read_pcap("capture_covert_2msdelay.pcap")
stamps_normal_delayed2 = read_pcap("capture_normal_2msdelay.pcap")
stamps_covert_delayed5 = read_pcap("capture_covert_5msdelay.pcap")
stamps_normal_delayed5 = read_pcap("capture_normal_5msdelay.pcap")
stamps_covert_delayed10 = read_pcap("capture_covert_10msdelay.pcap")
stamps_normal_delayed10 = read_pcap("capture_normal_10msdelay.pcap")
stamps_covert_delayed20 = read_pcap("capture_covert_20msdelay.pcap")
stamps_normal_delayed20 = read_pcap("capture_normal_20msdelay.pcap")
stamps_covert_delayed100 = read_pcap("capture_covert_100msdelay.pcap")
stamps_normal_delayed100 = read_pcap("capture_normal_100msdelay.pcap")


def remove_outliers(arr, thresh=3.0):
    """Return arr with points where |z-score| < thresh."""
    mu, std = arr.mean(), arr.std()
    if std == 0:
        return arr.copy()
    z = np.abs((arr - mu) / std)
    return arr[z < thresh]


diff_covert = np.diff(stamps_covert)
diff_normal = np.diff(stamps_normal)
# diff_normal_pcap = np.diff(stamps_normal_pcap)
# diff_covert_pcap = np.diff(stamps_covert_pcap)
diff_covert_d2 = remove_outliers(np.diff(stamps_covert_delayed2), thresh=3.0)
diff_normal_d2 = remove_outliers(np.diff(stamps_normal_delayed2), thresh=3.0)
diff_covert_d5 = remove_outliers(np.diff(stamps_covert_delayed5), thresh=3.0)
diff_normal_d5 = remove_outliers(np.diff(stamps_normal_delayed5), thresh=3.0)
diff_covert_d10 = remove_outliers(np.diff(stamps_covert_delayed10), thresh=3.0)
diff_normal_d10 = remove_outliers(np.diff(stamps_normal_delayed10), thresh=3.0)
diff_covert_d20 = remove_outliers(np.diff(stamps_covert_delayed20), thresh=3.0)
diff_normal_d20 = remove_outliers(np.diff(stamps_normal_delayed20), thresh=3.0)
diff_covert_d100 = remove_outliers(np.diff(stamps_covert_delayed100), thresh=3.0)
diff_normal_d100 = remove_outliers(np.diff(stamps_normal_delayed100), thresh=3.0)


def normalize(arr):
    return arr
    mn, mx = arr.min(), arr.max()
    return (arr - mn) / (mx - mn) if mx > mn else arr * 0


# normalize each
n_covert = normalize(diff_covert)
# n_covert_s = normalize(diff_covert_s)
n_normal = normalize(diff_normal)
# n_normal_pcap = normalize(diff_normal_pcap)
# n_covert_pcap = normalize(diff_covert_pcap)
n_covert_d2 = normalize(diff_covert_d2)
n_normal_d2 = normalize(diff_normal_d2)
n_covert_d5 = normalize(diff_covert_d5)
n_normal_d5 = normalize(diff_normal_d5)
n_covert_d10 = normalize(diff_covert_d10)
n_normal_d10 = normalize(diff_normal_d10)
n_covert_d20 = normalize(diff_covert_d20)
n_normal_d20 = normalize(diff_normal_d20)
n_covert_d100 = normalize(diff_covert_d100)
n_normal_d100 = normalize(diff_normal_d100)
#
# plot in 2×2 grid, each on its own scale 0–1
fig, axs = plt.subplots(3, 2, figsize=(10, 8))

axs[0, 0].plot(n_covert, label="Covert")
axs[0, 0].plot(n_normal, label="Normal")
axs[0, 0].set_title("No Delay")
axs[0, 0].legend()

# plt.plot(n_covert, label="Covert")
# # plt.plot(n_covert_s, label="Covert")
# plt.plot(n_normal, label="Normal")
# plt.plot(n_normal_pcap, label="Normal Pcap")
# plt.plot(n_covert_pcap, label="Covert Pcap")
# # plt.set_title("No Delay")
# plt.legend()

axs[0, 1].plot(n_covert_d2, label="Covert 2 ms")
axs[0, 1].plot(n_normal_d2, label="Normal 2 ms")
axs[0, 1].set_title("2 ms Delay")
axs[0, 1].legend()

axs[1, 0].plot(n_covert_d5, label="Covert 5 ms")
axs[1, 0].plot(n_normal_d5, label="Normal 5 ms")
axs[1, 0].set_title("5 ms Delay")
axs[1, 0].legend()

axs[1, 1].plot(n_covert_d10, label="Covert 10 ms")
axs[1, 1].plot(n_normal_d10, label="Normal 10 ms")
axs[1, 1].set_title("10 ms Delay")
axs[1, 1].legend()

axs[2, 0].plot(n_covert_d20, label="Covert 20 ms")
axs[2, 0].plot(n_normal_d20, label="Normal 20 ms")
axs[2, 0].set_title("20 ms Delay")
axs[2, 0].legend()

axs[2, 1].plot(n_covert_d100, label="Covert 100 ms")
axs[2, 1].plot(n_normal_d100, label="Normal 100 ms")
axs[2, 1].set_title("100 ms Delay")
axs[2, 1].legend()

for ax in axs.flat:
    ax.set_xlabel("Packet Index")
    ax.set_ylabel("Inter‑arrival Time")

fig.suptitle("Covert vs. Normal Traffic Across Delays", y=0.98)
plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig("covert_vs_normal_traffic.png", dpi=300, bbox_inches='tight')
plt.show()
