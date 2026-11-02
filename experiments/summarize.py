#!/usr/bin/env python3
"""Validate and summarize the five-fork PHAP desktop experiment.

Usage: python3 experiments/summarize.py OUTPUT_ROOT [--plot]

Requires fork-{1..5}/timings.csv, sizes.json and the public binary fixture dumps.
There must be 1,000 measured rows for each of the 14 named phases in every fork.
No timing observation is excluded, including failures, GC or scheduling outliers.
Pooled quantiles use linear interpolation (R/NumPy type 7). The mean and its 95%
Student-t interval use the five independent JVM fork means (df=4, t=2.776445),
not 5,000 independent message samples. The interval describes between-fork
variation on this host; it does not establish uncertainty across devices or links.
The optional PNG requires matplotlib; aggregation itself uses only the stdlib.
"""

import argparse
import csv
import json
import math
import statistics
from pathlib import Path


FORKS = tuple(range(1, 6))
SAMPLES = 1000
T_CRITICAL = 2.776445
PROFILES = ("SM2-only", "PHAP", "Falcon-message", "Dual-message")
PHASES = tuple(
    ["provider/" + name for name in ("SM2-sign", "SM2-verify", "Falcon-sign", "Falcon-verify")]
    + ["loopback/{}/{}".format(profile, mode) for profile in PROFILES for mode in ("cold", "warm")]
    + ["production-core/PHAP/" + mode for mode in ("cold", "warm")]
)
FIELDS = ("fork", "phase", "iteration", "elapsed_ns", "ack_elapsed_ns", "ok", "detail")


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def quantile(values, probability):
    """Linear-interpolated quantile, preserving all observations."""
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def distribution(values):
    return {
        "n": len(values),
        "mean_ms": statistics.fmean(values) / 1_000_000,
        "median_ms": quantile(values, 0.5) / 1_000_000,
        "p95_ms": quantile(values, 0.95) / 1_000_000,
        "min_ms": min(values) / 1_000_000,
        "max_ms": max(values) / 1_000_000,
    }


def read_rows(root):
    by_phase = {phase: {} for phase in PHASES}
    failures = []
    for fork in FORKS:
        path = root / "fork-{}".format(fork) / "timings.csv"
        groups = {phase: [] for phase in PHASES}
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            demand(tuple(reader.fieldnames or ()) == FIELDS, "Unexpected CSV header: {}".format(path))
            for line, row in enumerate(reader, start=2):
                location = "{}:{}".format(path, line)
                demand(None not in row and all(row[key] is not None for key in FIELDS), "Malformed CSV row: " + location)
                demand(row["phase"] in groups, "Unexpected phase at " + location)
                demand(int(row["fork"]) == fork, "Fork field mismatch at " + location)
                demand(row["ok"] in ("true", "false"), "Invalid Boolean at " + location)
                parsed = {
                    "fork": fork, "phase": row["phase"], "iteration": int(row["iteration"]),
                    "elapsed_ns": int(row["elapsed_ns"]), "ack_elapsed_ns": int(row["ack_elapsed_ns"]),
                    "ok": row["ok"] == "true", "detail": row["detail"],
                }
                demand(parsed["elapsed_ns"] >= 0 and parsed["ack_elapsed_ns"] >= 0, "Negative elapsed time at " + location)
                if parsed["phase"].startswith("loopback/"):
                    demand(parsed["ack_elapsed_ns"] >= parsed["elapsed_ns"], "ACK precedes receiver acceptance at " + location)
                else:
                    demand(parsed["ack_elapsed_ns"] == 0, "Unexpected non-network ACK time at " + location)
                groups[parsed["phase"]].append(parsed)
                if not parsed["ok"]:
                    failures.append(parsed)
        for phase, rows in groups.items():
            demand(len(rows) == SAMPLES, "{} fork {} has {} rows, expected {}".format(phase, fork, len(rows), SAMPLES))
            demand(sorted(row["iteration"] for row in rows) == list(range(SAMPLES)),
                   "Duplicated/missing iteration in {} fork {}".format(phase, fork))
            by_phase[phase][fork] = rows
    return by_phase, failures


def read_sizes(root):
    reference = None
    for fork in FORKS:
        directory = root / "fork-{}".format(fork)
        records = json.loads((directory / "sizes.json").read_text(encoding="utf-8"))
        demand(isinstance(records, list) and len(records) == 4, "Expected four size records in " + str(directory))
        records = sorted(records, key=lambda record: record["suite"])
        demand([record["suite"] for record in records] == [1, 2, 3, 4], "Size suite identifiers differ in " + str(directory))
        for suite, record in enumerate(records, start=1):
            body = (128, 128, 1025, 1025)[suite - 1]
            credential = (200, 866, 1763, 1763)[suite - 1]
            signature = (64, 64, 666, 730)[suite - 1]
            fragment_count = (credential + 255) // 256
            chunks = [min(256, credential - 256 * i) for i in range(fragment_count)]
            message = 92 + 128 + signature
            expected = {
                "suite": suite, "profile": PROFILES[suite - 1], "bodyBytes": body,
                "credentialBytes": credential, "messageSignatureBytes": signature,
                "signedInputBytes": 223, "fragmentPayloadBytes": chunks, "fragments": fragment_count,
                "messageWireBytes": message, "credentialFragmentWireBytes": credential + 44 * fragment_count,
                "coldCanonicalBytes": message + credential + 44 * fragment_count,
                "warmCanonicalBytes": message, "coldTestFramingBytes": 4 + 4 * (1 + fragment_count),
                "warmTestFramingBytes": 8,
            }
            demand(record == expected, "Unexpected size record for suite {} fork {}: {}".format(suite, fork, record))
            fixture = directory / "public-fixtures" / "suite-{}".format(suite)
            for filename, size in (("body.bin", body), ("credential.bin", credential), ("message-128.bin", message)):
                demand((fixture / filename).stat().st_size == size, "Binary size mismatch: " + str(fixture / filename))
            for index, chunk in enumerate(chunks, start=1):
                path = fixture / "fragment-{}.bin".format(index)
                demand(path.stat().st_size == 44 + chunk, "Fragment binary size mismatch: " + str(path))
        public = directory / "public-fixtures"
        demand((public / "ca-sm2-public.bin").stat().st_size == 65, "Invalid SM2 public key length")
        demand((public / "ca-falcon-public.bin").stat().st_size == 897, "Invalid Falcon public key length")
        if reference is None:
            reference = records
        else:
            demand(records == reference, "Size metadata differ between forks")
    return reference


def summarize_phase(forks):
    per_fork = []
    pooled = []
    for fork in FORKS:
        rows = forks[fork]
        values = [row["elapsed_ns"] for row in rows]
        pooled.extend(values)
        per_fork.append(dict(fork=fork, successes=sum(row["ok"] for row in rows),
                             failures=sum(not row["ok"] for row in rows), **distribution(values)))
    fork_means = [entry["mean_ms"] for entry in per_fork]
    mean = statistics.fmean(fork_means)
    standard_error = statistics.stdev(fork_means) / math.sqrt(len(fork_means))
    half_width = T_CRITICAL * standard_error
    result = dict(distribution(pooled), successes=sum(entry["successes"] for entry in per_fork),
                  failures=sum(entry["failures"] for entry in per_fork),
                  fork_means_ms=fork_means, mean_ci95_low_ms=mean - half_width,
                  mean_ci95_high_ms=mean + half_width, mean_ci95_half_width_ms=half_width,
                  per_fork=per_fork)
    ack = [row["ack_elapsed_ns"] for fork in FORKS for row in forks[fork]]
    if any(ack):
        result["sender_ack_elapsed"] = distribution(ack)
    return result


def make_plot(root, summaries):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Medians are bars; the separate dot is p95, not a confidence interval.
    colors = ("#637487", "#267A70", "#AD763B", "#805A91")
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                         "savefig.dpi": 240, "figure.dpi": 120})
    figure, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), sharey=True, layout="constrained")
    for axis, mode in zip(axes, ("cold", "warm")):
        entries = [summaries["loopback/{}/{}".format(profile, mode)] for profile in PROFILES]
        medians = [entry["median_ms"] for entry in entries]
        tails = [entry["p95_ms"] for entry in entries]
        axis.bar(range(4), medians, color=colors, width=0.62, zorder=3, label="Median")
        axis.scatter(range(4), tails, color="#202A35", s=25, zorder=4, marker="D", label="95th percentile")
        axis.set_xticks(range(4), ("SM2\nonly", "PHAP", "Falcon\nmessage", "Dual\nmessage"))
        axis.set_title("Cold credential cache" if mode == "cold" else "Warm credential cache")
        axis.grid(axis="y", color="#DDE2E6", linewidth=0.6, zorder=0)
        axis.set_ylim(bottom=0)
        for index, (median, tail) in enumerate(zip(medians, tails)):
            axis.annotate("{:.3f}".format(median), (index, median), xytext=(0, -5),
                          textcoords="offset points", ha="center", va="top", fontsize=9, color="white")
    axes[0].set_ylabel("Payload ready to authenticated delivery (ms)")
    axes[1].legend(frameon=False, loc="upper right", fontsize=9)
    figure.suptitle("Same-host TCP loopback, 128-byte payload; 5 JVM forks × 1,000 measured trials", fontsize=11)
    figure.savefig(root / "loopback_latency.png", facecolor="white")
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--plot", action="store_true", help="also write loopback_latency.png (requires matplotlib)")
    args = parser.parse_args()
    root = args.output_root.resolve()
    by_phase, failures = read_rows(root)
    sizes = read_sizes(root)
    summaries = {phase: summarize_phase(by_phase[phase]) for phase in PHASES}
    output = {
        "classification": "Single-host desktop JVM experiment; no Android/device or field-network timing claim",
        "validation": {"forks": list(FORKS), "phases_per_fork": len(PHASES), "measured_rows_per_phase_per_fork": SAMPLES,
                       "total_measured_rows": len(PHASES) * len(FORKS) * SAMPLES, "failed_rows": len(failures),
                       "all_expected_rows_present": True, "size_metadata_and_public_binary_lengths_consistent": True},
        "statistics": {
            "time_unit": "milliseconds", "quantile_definition": "linear interpolation, type 7",
            "sample_exclusion": "None; failures, GC and scheduling outliers are retained in timing distributions",
            "mean_interval": "Two-sided 95% Student-t interval over the five JVM fork means; df=4; t=2.776445",
            "independent_repetition_unit": "JVM fork; messages within a fork share keys, JIT, heap and host conditions",
            "limits": "Between-fork variation on this host does not quantify variation across devices or network links",
            "ack_metric": "Receiver-stop TTFA excludes return ACK; sender_ack_elapsed records the additional sender-observed interval separately",
        },
        "sizes": sizes, "phases": summaries, "failed_observations": failures,
    }
    (root / "summary.json").write_text(json.dumps(output, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    columns = ["phase", "n", "successes", "failures", "mean_ms", "mean_ci95_low_ms", "mean_ci95_high_ms",
               "median_ms", "p95_ms", "min_ms", "max_ms"] + ["fork_{}_mean_ms".format(fork) for fork in FORKS]
    with (root / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for phase, stats in summaries.items():
            row = {key: stats[key] for key in columns if key in stats}
            row["phase"] = phase
            row.update({"fork_{}_mean_ms".format(fork): mean for fork, mean in zip(FORKS, stats["fork_means_ms"])})
            writer.writerow(row)
    if args.plot:
        make_plot(root, summaries)
    print("Validated {} rows across 5 forks and 14 phases; {} failed observations retained.".format(
        output["validation"]["total_measured_rows"], len(failures)))
    print("Wrote " + str(root / "summary.csv") + " and " + str(root / "summary.json"))
    if args.plot:
        print("Wrote " + str(root / "loopback_latency.png"))


if __name__ == "__main__":
    main()
