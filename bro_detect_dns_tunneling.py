#!/usr/bin/env python3
from publicsuffix import PublicSuffixList
import gzip
import datetime
import os
import sys

dns_request_pos = 8  # FQDN Pos in BRO DNS Logs.

if __name__ == "__main__":
    # Check that the user has enter enough args.
    if len(sys.argv) != 4:
        print("Attempts to find instances of DNS tunneling by examining Bro DNS logs.")
        print("\nUsage: bro_log_dir output_dir whitelist_file")
        print("\nExample:")
        print("-" * 50)
        print(r"/nsm/bro/logs c:\results c:\whitelisted_domains.txt")
        sys.exit()

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    whitelist_file = sys.argv[3]

    # Instantiate the public suffix list
    psl = PublicSuffixList()

    # Dict to store results.
    results = {}

    # Sentry variable so that Python does not throw a wobbler (as the actual meaningful value is generated within a
    # conditional for loop).
    interval = ""

    # Get the whitelisted domains.
    with open(whitelist_file, "r", encoding="utf-8") as f:
        whitelist = [domain.strip() for domain in f if domain != "\n"]

    # Make the output Dir if needed.
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Get the time/date one hor ago.
    time_date_one_hour_ago = str(datetime.datetime.now() - datetime.timedelta(minutes=60))
    dir_to_search = time_date_one_hour_ago[:10]
    log_time_to_search = time_date_one_hour_ago[11:13]

    # Calculate the directory to search
    dir_to_search = os.path.join(input_dir, dir_to_search)

    for path, dirs, files in os.walk(dir_to_search):
        for filename in files:
            if "dns" in filename:
                # Get the position of the time part of the filename by looking for the first "." and adding one to it.
                time_pos = filename.find(".") + 1
                # Check if we have the correct file to search by searching the time_pos - time_pos + 2.
                if filename[time_pos:time_pos + 2] == log_time_to_search:
                    # Get the interval
                    interval = filename[time_pos:time_pos + 17]
                    # Build the fullpath.
                    fullpath = os.path.join(path, filename)
                    # Open the log
                    with gzip.open(fullpath, "r") as f:
                        for line in f:
                            # Decode the line as UTF-8 (line is encoded as bytes by gzip module).
                            line = line.decode("utf-8")
                            # Skip the headers.
                            if "#" in line:
                                continue
                            # Store the whole record.
                            whole_record = line.split()
                            # Store the FQDN resolved.
                            fqdn = whole_record[dns_request_pos]
                            # Work our the public suffix.
                            domain = psl.get_public_suffix(fqdn)
                            # Check if this domain is whitelisted.
                            if domain in whitelist:
                                continue
                            # Store the FQDN labels in an array.
                            fqdn_labels = fqdn.split(".")
                            # Work out how many labels we need to search (excluding the public suffix)
                            labels_to_search = len(fqdn_labels) - len(domain.split("."))
                            # Store a value of zero, to be incremented as the relevant labels are searched.
                            labels_to_search_aggregated_length = 0
                            # Iterate over the labels and get the char count.
                            for i in range(labels_to_search):
                                labels_to_search_aggregated_length += len(fqdn_labels[i])
                            # If the aggregated length of the labels is > 80, then we MAY have some DNS tunneling.
                            if labels_to_search_aggregated_length > 80:
                                # Check if the domain is in the results dict.
                                if domain not in results:
                                    results[domain] = []
                                # Append the results.
                                results[domain].append(fqdn)

                    if results:
                        # Open a text file to store te results.
                        report_file = os.path.join(output_dir, "{}.txt".format(time_date_one_hour_ago[:10]))
                        with open(os.path.join(report_file), "a+", encoding="utf-8") as f:
                            # Check if we need the header.
                            if os.path.getsize(report_file) == 0:
                                f.write("Number\tInterval\tDomain\tExample\n")
                            # Iterate over the actual results.
                            for fqdn in results:
                                f.write(str(len(results[fqdn])) + "\t" + interval + "\t" + fqdn + "\t"
                                        + results[fqdn][0].replace(".", "(.)") + "\n")
