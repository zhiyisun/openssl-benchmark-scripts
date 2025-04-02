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
                        if isinstance(result, list):
                            results.extend(result)
                        else:
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
    lines = content.splitlines()
    data_line = None
    target_algorithm = result["algorithm"].replace(" ", "-").upper()
    for line in reversed(lines):
        if line.upper().startswith(target_algorithm):
            data_line = line
            break
        elif "DONE" in line.upper() and target_algorithm in content.upper():
            # find the line before DONE
            for i in range(len(lines)-1, 0, -1):
                if lines[i].upper() == line.upper():
                    for j in range(i-1, 0, -1):
                        if "bytes" in lines[j] and target_algorithm in lines[j].upper():
                            data_line = lines[j]
                            break
                    break
            if data_line is None:
                print(f"Warning: Could not find data line in log: {filename}")
                return None
            else:
                break

    
    if data_line is None:
        print(f"Warning: Could not find data line in log: {filename}")
        return None

    parts = data_line.split()
    if len(parts) >= 7:
        try:
            result[f"bytes_16"] = convert_to_float(parts[-6])
            result[f"bytes_64"] = convert_to_float(parts[-5])
            result[f"bytes_256"] = convert_to_float(parts[-4])
            result[f"bytes_1024"] = convert_to_float(parts[-3])
            result[f"bytes_8192"] = convert_to_float(parts[-2])
            result[f"bytes_16384"] = convert_to_float(parts[-1])
        except ValueError as e:
            print(f"Error parsing {filename}: {e}")
            return None
    else:
        print(f"Warning: Could not parse data line in log: {filename}")
        return None
    return result

def parse_hash_algorithm(content, result, filename):
    lines = content.splitlines()
    data_line = None
    target_algorithm = result["algorithm"].upper()

    for line in reversed(lines):
        if target_algorithm in line.upper() and "k" in line and " " in line:
            data_line = line
            break

    if data_line is None:
        print(f"Warning: Could not find data line in log: {filename}")
        return None

    parts = data_line.split()
    if len(parts) >= 7:
        try:
            result[f"bytes_16"] = convert_to_float(parts[-6])
            result[f"bytes_64"] = convert_to_float(parts[-5])
            result[f"bytes_256"] = convert_to_float(parts[-4])
            result[f"bytes_1024"] = convert_to_float(parts[-3])
            result[f"bytes_8192"] = convert_to_float(parts[-2])
            result[f"bytes_16384"] = convert_to_float(parts[-1])
        except ValueError as e:
            print(f"Error parsing {filename}: {e}")
            return None
    else:
        print(f"Warning: Could not parse data line in log: {filename}")
        return None

    return result

def parse_rsa_algorithm(content, result, filename):
    lines = content.splitlines()
    
    table_starts = []
    for i, line in enumerate(lines):
        if "sign    verify    encrypt   decrypt   sign/s verify/s  encr./s  decr./s" in line:
            table_starts.append((i, "core"))
        elif "keygen    encaps    decaps keygens/s  encaps/s  decaps/s" in line:
            table_starts.append((i, "kem"))
        elif "keygen     signs    verify keygens/s    sign/s  verify/s" in line:
            table_starts.append((i, "sign"))

    if not table_starts:
        print(f"Warning: Could not find any table in log: {filename}")
        return None

    rsa_results = []
    for start_index, table_type in table_starts:
        data_line = ""
        if start_index + 1 < len(lines):
            # Correctly handle the data line based on table type
            if table_type == "core" or table_type == "kem" or table_type == "sign":
                data_line = lines[start_index + 1]
        else:
            print(f"Warning: Could not find data line in log: {filename} for table type {table_type}")
            continue
        
        parts = data_line.split()
        rsa_result = result.copy()
        rsa_result["table_type"] = table_type
        rsa_result["algorithm"] = result["algorithm"]
        rsa_result["mode"] = result["mode"]
        rsa_result["run"] = result["run"]

        if table_type == "core":
            if len(parts) >= 8:
                try:
                    rsa_result[f"sign_per_second"] = convert_to_float(parts[7])
                    rsa_result[f"verify_per_second"] = convert_to_float(parts[8])
                    rsa_result[f"encrypt_per_second"] = convert_to_float(parts[9])
                    rsa_result[f"decrypt_per_second"] = convert_to_float(parts[10])
                except ValueError as e:
                    print(f"Error parsing {filename}: {e}")
                    continue
            else:
                print(f"Warning: Could not parse data line in log: {filename} for table type {table_type}")
                continue
        elif table_type == "kem":
            if len(parts) >= 6:
                try:
                    rsa_result[f"keygen_per_second_kem"] = convert_to_float(parts[4])
                    rsa_result[f"encaps_per_second"] = convert_to_float(parts[5])
                    rsa_result[f"decaps_per_second"] = convert_to_float(parts[6])
                except ValueError as e:
                    print(f"Error parsing {filename}: {e}")
                    continue
            else:
                print(f"Warning: Could not parse data line in log: {filename} for table type {table_type}")
                continue
        elif table_type == "sign":
            if len(parts) >= 6:
                try:
                    rsa_result[f"keygen_per_second_sign"] = convert_to_float(parts[4])
                    rsa_result[f"sign_per_second_sign"] = convert_to_float(parts[5])
                    rsa_result[f"verify_per_second_sign"] = convert_to_float(parts[6])
                except ValueError as e:
                    print(f"Error parsing {filename}: {e}")
                    continue
            else:
                print(f"Warning: Could not parse data line in log: {filename} for table type {table_type}")
                continue
        rsa_results.append(rsa_result)

    return rsa_results

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
    elif 'cpuinfo:' in value:
        raise ValueError("cpuinfo: is not a number")
    elif 'keygens/s' in value:
        return float(value.replace('keygens/s', ''))
    elif 'encaps/s' in value:
        return float(value.replace('encaps/s', ''))
    elif 'decaps/s' in value:
        return float(value.replace('decaps/s', ''))
    elif 'sign/s' in value:
        return float(value.replace('sign/s', ''))
    elif 'verify/s' in value:
        return float(value.replace('verify/s', ''))
    elif 'encr./s' in value:
        return float(value.replace('encr./s', ''))
    elif 'decr./s' in value:
        return float(value.replace('decr./s', ''))
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
        key = (result["algorithm"], result["mode"], result.get("table_type", "none"))
        grouped_results[key].append(result)

    for (algorithm, mode, table_type), group in grouped_results.items():
        if len(group) < 3:
            print(f"Warning: Less than 3 runs for {algorithm} {mode} {table_type}, cannot calculate average.")
            continue
        
        avg_result = {
            "algorithm": algorithm,
            "mode": mode,
            "run": "average",
        }
        if table_type != "none":
            avg_result["table_type"] = table_type

        if algorithm.startswith("aes") or algorithm.startswith("chacha"):
            avg_result[f"bytes_16"] = sum(r.get("bytes_16",0) for r in group) / len(group)
            avg_result[f"bytes_64"] = sum(r.get("bytes_64",0) for r in group) / len(group)
            avg_result[f"bytes_256"] = sum(r.get("bytes_256",0) for r in group) / len(group)
            avg_result[f"bytes_1024"] = sum(r.get("bytes_1024",0) for r in group) / len(group)
            avg_result[f"bytes_8192"] = sum(r.get("bytes_8192",0) for r in group) / len(group)
            avg_result[f"bytes_16384"] = sum(r.get("bytes_16384",0) for r in group) / len(group)
        elif algorithm.startswith("sha"):
            avg_result[f"bytes_16"] = sum(r.get("bytes_16",0) for r in group) / len(group)
            avg_result[f"bytes_64"] = sum(r.get("bytes_64",0) for r in group) / len(group)
            avg_result[f"bytes_256"] = sum(r.get("bytes_256",0) for r in group) / len(group)
            avg_result[f"bytes_1024"] = sum(r.get("bytes_1024",0) for r in group) / len(group)
            avg_result[f"bytes_8192"] = sum(r.get("bytes_8192",0) for r in group) / len(group)
            avg_result[f"bytes_16384"] = sum(r.get("bytes_16384",0) for r in group) / len(group)
        elif algorithm.startswith("rsa"):
            avg_result[f"sign_per_second"] = sum(r.get("sign_per_second",0) for r in group) / len(group)
            avg_result[f"verify_per_second"] = sum(r.get("verify_per_second",0) for r in group) / len(group)
            avg_result[f"encrypt_per_second"] = sum(r.get("encrypt_per_second",0) for r in group) / len(group)
            avg_result[f"decrypt_per_second"] = sum(r.get("decrypt_per_second",0) for r in group) / len(group)
            avg_result[f"keygen_per_second_kem"] = sum(r.get("keygen_per_second_kem",0) for r in group) / len(group)
            avg_result[f"encaps_per_second"] = sum(r.get("encaps_per_second",0) for r in group) / len(group)
            avg_result[f"decaps_per_second"] = sum(r.get("decaps_per_second",0) for r in group) / len(group)
            avg_result[f"keygen_per_second_sign"] = sum(r.get("keygen_per_second_sign",0) for r in group) / len(group)
            avg_result[f"sign_per_second_sign"] = sum(r.get("sign_per_second_sign",0) for r in group) / len(group)
            avg_result[f"verify_per_second_sign"] = sum(r.get("verify_per_second_sign",0) for r in group) / len(group)

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
        table_type = result.get("table_type", "none")
        
        if run == "average":
            run_sort_value = float('inf')  # Place "average" at the end
        else:
            run_sort_value = run
        return (algorithm, mode, table_type, run_sort_value)

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
    
    # Reorder the fieldnames to match the desired column order
    ordered_fieldnames = []
    
    # Add the fixed columns first
    fixed_columns = ["algorithm", "mode", "run", "table_type"]
    for col in fixed_columns:
        if col in fieldnames:
            ordered_fieldnames.append(col)
            fieldnames.remove(col)
    
    # Add the byte columns in the specified order
    byte_columns = ["bytes_16", "bytes_64", "bytes_256", "bytes_1024", "bytes_8192", "bytes_16384"]
    for col in byte_columns:
        if col in fieldnames:
            ordered_fieldnames.append(col)
            fieldnames.remove(col)

    # Add the rsa core columns
    rsa_core_columns = ["sign_per_second", "verify_per_second", "encrypt_per_second", "decrypt_per_second"]
    for col in rsa_core_columns:
        if col in fieldnames:
            ordered_fieldnames.append(col)
            fieldnames.remove(col)
    
    # Add the rsa kem columns
    rsa_kem_columns = ["keygen_per_second_kem", "encaps_per_second", "decaps_per_second"]
    for col in rsa_kem_columns:
        if col in fieldnames:
            ordered_fieldnames.append(col)
            fieldnames.remove(col)

    # Add the rsa sign columns
    rsa_sign_columns = ["keygen_per_second_sign", "sign_per_second_sign", "verify_per_second_sign"]
    for col in rsa_sign_columns:
        if col in fieldnames:
            ordered_fieldnames.append(col)
            fieldnames.remove(col)

    # Add the remaining columns
    ordered_fieldnames.extend(sorted(list(fieldnames)))
    
    with open(csv_filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=ordered_fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"Results written to {csv_filename}")

def write_algorithm_results_to_csv(results, output_dir):
    """
    Writes the parsed benchmark results to separate CSV files for each algorithm.

    Args:
        results: A list of dictionaries containing the benchmark results.
        output_dir: The directory to write the CSV files to.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    grouped_results = defaultdict(list)
    for result in results:
        grouped_results[result["algorithm"]].append(result)

    for algorithm, algorithm_results in grouped_results.items():
        csv_filename = os.path.join(output_dir, f"openssl_{algorithm}_benchmark_results.csv")
        
        fieldnames = set()
        for result in algorithm_results:
            fieldnames.update(result.keys())

        ordered_fieldnames = ["algorithm", "mode", "run", "table_type"]
        
        # Add the byte columns in the specified order if they exist
        byte_columns = ["bytes_16", "bytes_64", "bytes_256", "bytes_1024", "bytes_8192", "bytes_16384"]
        for col in byte_columns:
            if col in fieldnames:
                ordered_fieldnames.append(col)
                fieldnames.remove(col)
        
        # Add the rsa core columns
        rsa_core_columns = ["sign_per_second", "verify_per_second", "encrypt_per_second", "decrypt_per_second"]
        for col in rsa_core_columns:
            if col in fieldnames:
                ordered_fieldnames.append(col)
                fieldnames.remove(col)
        
        # Add the rsa kem columns
        rsa_kem_columns = ["keygen_per_second_kem", "encaps_per_second", "decaps_per_second"]
        for col in rsa_kem_columns:
            if col in fieldnames:
                ordered_fieldnames.append(col)
                fieldnames.remove(col)

        # Add the rsa sign columns
        rsa_sign_columns = ["keygen_per_second_sign", "sign_per_second_sign", "verify_per_second_sign"]
        for col in rsa_sign_columns:
            if col in fieldnames:
                ordered_fieldnames.append(col)
                fieldnames.remove(col)

        # Add the remaining columns
        ordered_fieldnames.extend(sorted(list(fieldnames - set(ordered_fieldnames))))

        with open(csv_filename, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=ordered_fieldnames)
            writer.writeheader()
            for row in algorithm_results:
                writer.writerow(row)

        print(f"{algorithm} Results written to {csv_filename}")

def main():
    """
    Main function to parse OpenSSL benchmark logs and generate CSV files.
    """
    log_dir = "openssl-benchmarks"  # Replace with your log directory if different
    output_dir = "algorithm_results" # Directory to store the algorithm-specific CSVs
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
    write_algorithm_results_to_csv(all_results, output_dir)


if __name__ == "__main__":
    main()
