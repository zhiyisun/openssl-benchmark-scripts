import os
import re
import csv
import statistics

def parse_rsa_line(line):
    """Parses a line from an RSA log file."""
    parts = line.split()
    if len(parts) != 11:
        return None
    try:
        block_size = int(parts[1])
        sign_per_sec = float(parts[7])
        verify_per_sec = float(parts[8])
        encrypt_per_sec = float(parts[9])
        decrypt_per_sec = float(parts[10])
        return {
            "algorithm": parts[0],
            "block_size": block_size,
            "sign/s": sign_per_sec,
            "verify/s": verify_per_sec,
            "encr./s": encrypt_per_sec,
            "decr./s": decrypt_per_sec,
        }
    except ValueError:
        return None

def parse_other_line(line):
    """Parses a line from a non-RSA log file."""
    parts = line.split()
    if len(parts) != 7:
        return None
    try:
        sizes = [16, 64, 256, 1024, 8192, 16384]
        data = {}
        for i, size in enumerate(sizes):
            data[f"{size}"] = float(parts[i + 1].replace('k', '')) * 1000
        return {"algorithm": parts[0], **data}
    except ValueError:
        return None

def parse_log_file(filepath):
    """Parses a single log file."""
    results = {}
    parsing = False
    with open(filepath, "r") as f:
        for line in f:
            if line.startswith("CPUINFO"):
                parsing = True
                continue
            if not parsing:
                continue

            if line.startswith("rsa") and "bits" in line:
                rsa_data = parse_rsa_line(line)
                if rsa_data:
                    algorithm = rsa_data["algorithm"]
                    if algorithm not in results:
                        results[algorithm] = []
                    results[algorithm].append(rsa_data)
            else:
                other_data = parse_other_line(line)
                if other_data:
                    algorithm = other_data["algorithm"]
                    if algorithm not in results:
                        results[algorithm] = []
                    results[algorithm].append(other_data)
    return results

def calculate_averages(data):
    """Calculates the average for each metric across iterations."""
    averages = {}
    for algorithm, iterations in data.items():
        if not iterations:
            continue
        
        first_iteration = iterations[0]
        if "block_size" in first_iteration:
            # RSA-like data
            block_sizes = sorted(list(set(item["block_size"] for item in iterations)))
            averages[algorithm] = []
            for block_size in block_sizes:
                block_iterations = [item for item in iterations if item["block_size"] == block_size]
                if not block_iterations:
                    continue
                avg_sign = statistics.mean([item["sign/s"] for item in block_iterations])
                avg_verify = statistics.mean([item["verify/s"] for item in block_iterations])
                avg_encr = statistics.mean([item["encr./s"] for item in block_iterations])
                avg_decr = statistics.mean([item["decr./s"] for item in block_iterations])
                averages[algorithm].append({
                    "algorithm": algorithm,
                    "block_size": block_size,
                    "sign/s": avg_sign,
                    "verify/s": avg_verify,
                    "encr./s": avg_encr,
                    "decr./s": avg_decr,
                    "type": "average"
                })
        else:
            # Other data
            sizes = [16, 64, 256, 1024, 8192, 16384]
            averages[algorithm] = []
            avg_data = {}
            for size in sizes:
                avg_data[str(size)] = statistics.mean([item[str(size)] for item in iterations])
            averages[algorithm].append({"algorithm": algorithm, "type": "average", **avg_data})
    return averages

def write_to_csv(output_dir, mode, data):
    """Writes the parsed data to CSV files."""
    os.makedirs(output_dir, exist_ok=True)
    for algorithm, iterations in data.items():
        filepath = os.path.join(output_dir, f"{mode}_{algorithm}.csv")
        if not iterations:
            continue
        
        first_iteration = iterations[0]
        if "block_size" in first_iteration:
            # RSA-like data
            fieldnames = ["type", "algorithm", "block_size", "sign/s", "verify/s", "encr./s", "decr./s"]
        else:
            # Other data
            fieldnames = ["type", "algorithm", "16", "64", "256", "1024", "8192", "16384"]

        with open(filepath, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for iteration in iterations:
                iteration["type"] = "iteration"
                writer.writerow(iteration)
            
            averages = calculate_averages({algorithm: iterations})
            if algorithm in averages:
                for avg in averages[algorithm]:
                    writer.writerow(avg)

def main():
    """Main function to orchestrate the parsing and CSV generation."""
    log_dir = "openssl-benchmarks"
    output_dir = "benchmark_results"

    single_mode_results = {}
    multi_mode_results = {}

    for filename in os.listdir(log_dir):
        if filename.endswith(".log"):
            filepath = os.path.join(log_dir, filename)
            results = parse_log_file(filepath)
            if "single" in filename:
                for algorithm, data in results.items():
                    if algorithm not in single_mode_results:
                        single_mode_results[algorithm] = []
                    single_mode_results[algorithm].extend(data)
            elif "multi" in filename:
                for algorithm, data in results.items():
                    if algorithm not in multi_mode_results:
                        multi_mode_results[algorithm] = []
                    multi_mode_results[algorithm].extend(data)

    write_to_csv(output_dir, "single", single_mode_results)
    write_to_csv(output_dir, "multi", multi_mode_results)

if __name__ == "__main__":
    main()
