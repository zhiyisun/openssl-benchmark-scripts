import os
import re
import csv
import subprocess
from collections import defaultdict

def parse_openssl_benchmark_logs(log_dir):
    """
    Parses OpenSSL benchmark log files and extracts relevant data.

    Args:
        log_dir: The directory containing the OpenSSL benchmark log files.

    Returns:
        A list of dictionaries, where each dictionary represents a benchmark run
        and contains the extracted data.
    """

    results = []
    for filename in os.listdir(log_dir):
        if filename.endswith(".log"):
            filepath = os.path.join(log_dir, filename)
            try:
                with open(filepath, "r") as f:
                    content = f.read()
                    result = parse_single_log(content, filename)
                    if result:
                        results.append(result)
            except Exception as e:
                print(f"Error parsing {filename}: {e}")
    return results


def parse_single_log(content, filename):
    """
    Parses a single OpenSSL benchmark log file and extracts relevant data.

    Args:
        content: The content of the log file as a string.
        filename: The name of the log file.

    Returns:
        A dictionary containing the extracted data, or None if parsing fails.
    """
    
    match = re.match(r"(.+?)_(single|multi)_run(\d+)\.log", filename)
    if not match:
        print(f"Warning: Could not parse filename: {filename}")
        return None
    
    algorithm, mode, run_number = match.groups()
    
    if algorithm.startswith("-evp"):
        algorithm = algorithm.replace("-evp_", "")
        algorithm = algorithm.replace("_", " ")

    result = {
        "algorithm": algorithm,
        "mode": mode,
        "run": int(run_number),
    }

    if algorithm.startswith("aes") or algorithm.startswith("chacha"):
        # Parse -evp algorithms
        result = parse_evp_algorithm(content, result, filename)
    elif algorithm.startswith("sha"):
        # Parse hash algorithms
        result = parse_hash_algorithm(content, result, filename)
    elif algorithm.startswith("rsa"):
        # Parse RSA algorithms
        result = parse_rsa_algorithm(content, result, filename)
    else:
        print(f"Warning: Unknown algorithm type: {algorithm} in {filename}")
        return None

    return result

def parse_evp_algorithm(content, result, filename):
    # Find the line with "type" and the header
    type_line_index = -1
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "type" in line and "16 bytes" in line:
            type_line_index = i
            break
    
    if type_line_index == -1:
        #print(f"Warning: Could not find 'type' header in log: {filename}")
        return None

    for line in lines[type_line_index+1:]:
        if line.strip() == "":
            continue
        parts = line.split()
        if len(parts) >= 7:
            try:
                result[f"bytes_16"] = convert_to_float(parts[1])
                result[f"bytes_64"] = convert_to_float(parts[2])
                result[f"bytes_256"] = convert_to_float(parts[3])
                result[f"bytes_1024"] = convert_to_float(parts[4])
                result[f"bytes_8192"] = convert_to_float(parts[5])
                result[f"bytes_16384"] = convert_to_float(parts[6])
                break
            except ValueError as e:
                print(f"Error parsing {filename}: {e}")
                return None
    return result

def parse_hash_algorithm(content, result, filename):
    lines = content.splitlines()
    for line in lines:
        if "bytes per second" in line:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    # Check if the first part is a number
                    if parts[0].lower() == "the":
                        continue
                    result[f"bytes_16384"] = convert_to_float(parts[0])
                    break
                except ValueError as e:
                    print(f"Error parsing {filename}: {e}")
                    return None
    return result

def parse_rsa_algorithm(content, result, filename):
    lines = content.splitlines()
    
    # Find the line with "sign    verify    sign/s verify/s"
    header_line_index = -1
    for i, line in enumerate(lines):
        if "sign" in line and "verify" in line and "sign/s" in line and "verify/s" in line:
            header_line_index = i
            break
    
    if header_line_index == -1:
        print(f"Warning: Could not find 'sign/s verify/s' header in log: {filename}")
        return None

    data_line = ""
    if header_line_index + 1 < len(lines):
        data_line = lines[header_line_index + 1]
    else:
        print(f"Warning: Could not find data line in log: {filename}")
        return None
    
    parts = data_line.split()
    
    if len(parts) >= 4:
        try:
            # Check if the third part is a number
            if not parts[2].replace(".", "").isdigit():
                return None
            result[f"sign_per_second"] = convert_to_float(parts[2])
            result[f"verify_per_second"] = convert_to_float(parts[3])
        except ValueError as e:
            print(f"Error parsing {filename}: {e}")
            return None
    else:
        print(f"Warning: Could not parse data line in log: {filename}")
        return None
    return result

def convert_to_float(value):
    """
    Converts a string value (potentially with 'k', 'M', or 's' suffix) to a float.
    """
    value = value.lower()
    if 'k' in value:
        return float(value.replace('k', '')) * 1000
    elif 'm' in value:
        return float(value.replace('m', '')) * 1000000
    elif 's' in value:
        return float(value.replace('s', ''))
    elif 'bit' in value:
        return 0
    else:
        return float(value)

def calculate_averages(results):
    """
    Calculates the average benchmark results for each algorithm and mode.

    Args:
        results: A list of dictionaries containing the benchmark results.

    Returns:
        A list of dictionaries containing the average results.
    """
    averages = []
    grouped_results = defaultdict(list)

    for result in results:
        key = (result["algorithm"], result["mode"])
        grouped_results[key].append(result)

    for (algorithm, mode), group in grouped_results.items():
        if len(group) < 3:
            print(f"Warning: Less than 3 runs for {algorithm} {mode}, cannot calculate average.")
            continue
        
        avg_result = {
            "algorithm": algorithm,
            "mode": mode,
            "run": "average",
        }
        if algorithm.startswith("aes") or algorithm.startswith("chacha"):
            avg_result[f"bytes_16"] = sum(r.get("bytes_16",0) for r in group) / len(group)
            avg_result[f"bytes_64"] = sum(r.get("bytes_64",0) for r in group) / len(group)
            avg_result[f"bytes_256"] = sum(r.get("bytes_256",0) for r in group) / len(group)
            avg_result[f"bytes_1024"] = sum(r.get("bytes_1024",0) for r in group) / len(group)
            avg_result[f"bytes_8192"] = sum(r.get("bytes_8192",0) for r in group) / len(group)
            avg_result[f"bytes_16384"] = sum(r.get("bytes_16384",0) for r in group) / len(group)
        elif algorithm.startswith("sha"):
            avg_result[f"bytes_16384"] = sum(r.get("bytes_16384",0) for r in group) / len(group)
        elif algorithm.startswith("rsa"):
            avg_result[f"sign_per_second"] = sum(r.get("sign_per_second",0) for r in group) / len(group)
            avg_result[f"verify_per_second"] = sum(r.get("verify_per_second",0) for r in group) / len(group)
        averages.append(avg_result)

    return averages

def sort_results(results):
    """
    Sorts the benchmark results by algorithm and mode.

    Args:
        results: A list of dictionaries containing the benchmark results.

    Returns:
        A sorted list of dictionaries.
    """
    def sort_key(result):
        algorithm = result["algorithm"]
        mode = result["mode"]
        run = result["run"]
        
        if run == "average":
            run_sort_value = float('inf')  # Place "average" at the end
        else:
            run_sort_value = run
        return (algorithm, mode, run_sort_value)

    return sorted(results, key=sort_key)

def write_results_to_csv(results, csv_filename):
    """
    Writes the parsed benchmark results to a CSV file.

    Args:
        results: A list of dictionaries containing the benchmark results.
        csv_filename: The name of the CSV file to write to.
    """

    if not results:
        print("No results to write to CSV.")
        return

    fieldnames = set()
    for result in results:
        fieldnames.update(result.keys())
    fieldnames = sorted(list(fieldnames))

    with open(csv_filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"Results written to {csv_filename}")


def main():
    """
    Main function to parse OpenSSL benchmark logs and generate a CSV file.
    """
    log_dir = "openssl-benchmarks"  # Replace with your log directory if different
    csv_filename = "openssl_benchmark_results.csv"

    if not os.path.exists(log_dir):
        print(f"Error: Log directory '{log_dir}' not found.")
        return
    
    results = parse_openssl_benchmark_logs(log_dir)
    if not results:
        print("No valid results found.")
        return
    
    averages = calculate_averages(results)
    all_results = sort_results(results + averages)
    write_results_to_csv(all_results, csv_filename)


if __name__ == "__main__":
    main()
